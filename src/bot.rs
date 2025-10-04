use crate::challenge::Quiz;
use crate::config::{Action, Config};
use crate::telegram::{self, ForwardMessage, PinChatMessage, WebhookReply};

use std::collections::HashMap;
use std::time::SystemTime;

use rust_persian_tools::{arabic_chars::HasArabic, digits::DigitsEn2Fa, persian_chars::HasPersian};
use telegram_types::bot::{
    methods::{
        AnswerCallbackQuery, ApproveJoinRequest, ChatTarget, DeclineJoinRequest, DeleteMessage,
        GetChatMember, ReplyMarkup, RestrictChatMember, SendMessage,
    },
    types::{
        ChatId, ChatMember, ChatMemberStatus, ChatPermissions, InlineKeyboardButton,
        InlineKeyboardButtonPressed, InlineKeyboardMarkup, Message, MessageId, ParseMode, Update,
        UpdateContent, User, UserId,
    },
};
use worker::*;

const JOIN_PREFIX: &str = "_JOIN_";
type FnCmd = dyn Fn(&Bot, &Message) -> Result<Response>;

#[derive(serde::Serialize, serde::Deserialize)]
struct ReportEntry {
    group_id: i64,
    reported_by: i64,
    timestamp: u64,
}

pub struct Bot {
    _token: String,
    kv: kv::KvStore,
    pub commands: HashMap<String, Box<FnCmd>>,
    pub config: Config,
}

impl Bot {
    pub fn new(_token: String, config: String, kv: kv::KvStore) -> Result<Self> {
        let config: Config =
            toml::from_str(&config).map_err(|e| Error::RustError(e.to_string()))?;

        Ok(Self {
            _token,
            kv,
            config,
            commands: HashMap::new(),
        })
    }

    pub fn reply(&self, msg: &Message, text: &str) -> Result<Response> {
        let message_id = msg
            .reply_to_message
            .as_ref()
            .map(|x| x.message_id)
            .unwrap_or(msg.message_id);

        Response::from_json(&WebhookReply::from(
            SendMessage::new(ChatTarget::Id(msg.chat.id), text)
                .parse_mode(ParseMode::Markdown)
                .reply(message_id),
        ))
    }

    pub fn send(&self, chat_id: ChatId, text: &str) -> Result<Response> {
        Response::from_json(&WebhookReply::from(SendMessage::new(
            ChatTarget::Id(chat_id),
            text,
        )))
    }

    pub fn pin(&self, msg: &Message) -> Result<Response> {
        let chat_id = msg.chat.id;
        let message_id = msg
            .reply_to_message
            .as_ref()
            .map(|x| x.message_id)
            .unwrap_or(msg.message_id);

        Response::from_json(&WebhookReply::from(PinChatMessage {
            chat_id,
            message_id,
        }))
    }

    pub fn forward(&self, msg: &Message, chat_id: ChatId) -> Result<Response> {
        let from_chat_id = msg.chat.id;
        let message_id = msg.message_id;

        Response::from_json(&WebhookReply::from(ForwardMessage {
            chat_id,
            from_chat_id,
            message_id,
        }))
    }

    pub fn approve_join_request(&self, chat_id: ChatId, user_id: UserId) -> Result<Response> {
        Response::from_json(&WebhookReply::from(ApproveJoinRequest {
            chat_id: ChatTarget::Id(chat_id),
            user_id,
        }))
    }

    pub fn decline_join_request(&self, chat_id: ChatId, user_id: UserId) -> Result<Response> {
        Response::from_json(&WebhookReply::from(DeclineJoinRequest {
            chat_id: ChatTarget::Id(chat_id),
            user_id,
        }))
    }

    pub async fn remove_expired_join_requests(&self) -> Result<()> {
        const TTL_LIMIT: u64 = 7 * 60;

        let keys = self
            .kv
            .list()
            .prefix(JOIN_PREFIX.to_string())
            .execute()
            .await?
            .keys;

        for key in keys {
            if let Some(ttl) = key.expiration {
                let now = Date::now().as_millis() / 1000;
                if ttl - now < TTL_LIMIT {
                    let (chat_id, message_id) = extract_key_details(&key.name);
                    let _ = telegram::send_json_request(
                        &self._token,
                        DeleteMessage {
                            chat_id: ChatTarget::Id(chat_id),
                            message_id,
                        },
                    )
                    .await;
                }
            }
        }

        Ok(())
    }

    async fn chat_join_request(&self, user: &User, chat_id: ChatId) -> Result<Response> {
        let user_mention = format!("[{}](tg://user?id={})", user.first_name, user.id.0);

        let quiz = Quiz::new();
        let message = format!(include_str!("./response/join"), user_mention, quiz.encode());

        let keys = quiz
            .choices()
            .iter()
            .map(|x| InlineKeyboardButton {
                text: x.clone(),
                pressed: InlineKeyboardButtonPressed::CallbackData(x.clone()),
            })
            .collect::<Vec<InlineKeyboardButton>>();

        let response: Message = telegram::send_json_request(
            &self._token,
            SendMessage::new(ChatTarget::Id(chat_id), message)
                .parse_mode(ParseMode::Markdown)
                .reply_markup(ReplyMarkup::InlineKeyboard(InlineKeyboardMarkup {
                    inline_keyboard: vec![keys],
                })),
        )
        .await?
        .json()
        .await?;

        let message_id = response.message_id;
        let _ = self
            .kv
            .put(
                &format!("{}{}:{}", JOIN_PREFIX, chat_id.0, message_id.0),
                user.id.0,
            )?
            .expiration_ttl(10 * 60)
            .execute()
            .await?;

        Response::empty()
    }

    async fn restrict_user(&self, user: &User, chat_id: ChatId) {
        let _ = telegram::send_json_request(
            &self._token,
            RestrictChatMember {
                chat_id: ChatTarget::Id(chat_id),
                user_id: user.id,
                permissions: ChatPermissions {
                    can_send_messages: false,
                },
            },
        )
        .await;
    }

    async fn send_welcome_for_new_member(&self, user: &User, chat_id: ChatId) -> Result<()> {
        let user_mention = format!("[{}](tg://user?id={})", user.first_name, user.id.0);
        let welcome_text = format!("کاربر جدید جوین شد: {} (ID: {})", user_mention, user.id.0);

        let report_button = vec![vec![InlineKeyboardButton {
            text: "Report".to_string(),
            pressed: InlineKeyboardButtonPressed::CallbackData(format!("report:{}", user.id.0)),
        }]];

        let markup = ReplyMarkup::InlineKeyboard(InlineKeyboardMarkup {
            inline_keyboard: report_button,
        });

        let _ = telegram::send_json_request(
            &self._token,
            SendMessage::new(ChatTarget::Id(chat_id), welcome_text)
                .parse_mode(ParseMode::Markdown)
                .reply_markup(markup),
        )
        .await?;

        Ok(())
    }

    async fn log_spammer(&self, user_id: i64, group_id: i64, reported_by: i64) -> Result<()> {
        let key = format!("spammers:{}", user_id);
        let get_res = self.kv.get(&key).text().await?;

        let mut entries: Vec<ReportEntry> = if let Some(json_str) = get_res {
            serde_json::from_str(&json_str).unwrap_or_default()
        } else {
            Vec::new()
        };

        if !entries.iter().any(|e| e.group_id == group_id) {
            entries.push(ReportEntry {
                group_id,
                reported_by,
                timestamp: SystemTime::now()
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0),
            });
        }

        let json_value =
            serde_json::to_string(&entries).map_err(|e| Error::RustError(e.to_string()))?;
        self.kv.put(&key, json_value)?.execute().await?;

        Ok(())
    }

    pub async fn process(&self, update: &Update) -> Result<Response> {
        match &update.content {
            Some(UpdateContent::Message(m)) => {
                if !m.new_chat_members.is_empty() {
                    let new_members = &m.new_chat_members;
                    if !self.config.bot.allowed_chats_id.contains(&m.chat.id) {
                        return Response::empty();
                    }
                    if let Some(user) = new_members.first() {
                        if user.first_name.has_persian(true) || user.first_name.has_arabic() {
                            return Response::empty();
                        }
                        self.send_welcome_for_new_member(user, m.chat.id).await?;
                        return Response::empty();
                    }
                }

                if !self.config.bot.allowed_chats_id.contains(&m.chat.id) {
                    return self.forward(&m, self.config.bot.report_chat_id);
                }
                for rule in &self.config.bot.rules {
                    for word in &rule.contains {
                        if m.text
                            .as_ref()
                            .map(|t| t.contains(word))
                            .unwrap_or_default()
                        {
                            match rule.action {
                                Action::Block => {
                                    if let Some(u) = &m.from {
                                        self.restrict_user(&u, m.chat.id).await;
                                    }
                                }
                            }
                            return self.forward(&m, self.config.bot.report_chat_id);
                        }
                    }
                }
                if m.message_id.0 & (m.message_id.0 - 1) == 0 {
                    let reply = format!(
                        include_str!("./response/easter-egg"),
                        m.message_id.0.digits_en_to_fa()
                    );
                    return self.reply(m, &reply);
                }
                if let Some(command) = m
                    .text
                    .as_ref()
                    .map(|t| t.trim())
                    .filter(|t| t.starts_with("!"))
                    .and_then(|t| self.commands.get(t))
                {
                    return command(self, &m);
                }
            }
            Some(UpdateContent::ChatJoinRequest(r)) => {
                if !self.config.bot.allowed_chats_id.contains(&r.chat.id) {
                    return Response::empty();
                }
                if r.from.first_name.has_persian(true) || r.from.first_name.has_arabic() {
                    return Response::empty();
                }
                return self.chat_join_request(&r.from, r.chat.id).await;
            }
            Some(UpdateContent::CallbackQuery(q)) => {
                if let Some(msg) = &q.message {
                    let key = format!("{}{}:{}", JOIN_PREFIX, msg.chat.id.0, msg.message_id.0);

                    let assigned_user = self.kv.get(&key).text().await?.unwrap_or_default();
                    let answered_user = q.from.id.0.to_string();

                    if assigned_user == answered_user {
                        if let Some(text) = &msg.text {
                            let quiz = Quiz::from_str(&extract_question(&text));
                            let answer = &quiz.answer().to_string();

                            let _ = telegram::send_json_request(
                                &self._token,
                                DeleteMessage {
                                    chat_id: ChatTarget::Id(msg.chat.id),
                                    message_id: msg.message_id,
                                },
                            )
                            .await;
                            self.kv.delete(&key).await?;

                            return if q.data.as_ref().map(|x| x == answer).unwrap_or_default() {
                                self.approve_join_request(msg.chat.id, q.from.id)
                            } else {
                                self.decline_join_request(msg.chat.id, q.from.id)
                            };
                        }
                    }

                    if let Some(data) = &q.data {
                        if data.starts_with("report:") {
                            let parts: Vec<&str> = data.split(':').collect();
                            if parts.len() == 2 {
                                let reported_id = parts[1]
                                    .parse::<i64>()
                                    .map_err(|_| Error::RustError("Invalid user ID".to_string()))?;

                                let is_admin = if self
                                    .config
                                    .bot
                                    .admin_users_id
                                    .contains(&q.from.id)
                                {
                                    true
                                } else {
                                    let get_member_res = telegram::send_json_request(
                                        &self._token,
                                        GetChatMember {
                                            chat_id: ChatTarget::Id(msg.chat.id),
                                            user_id: q.from.id,
                                        },
                                    )
                                    .await?
                                    .json::<ChatMember>()
                                    .await;

                                    match get_member_res {
                                        Ok(member) => {
                                            member.status == ChatMemberStatus::Administrator
                                                || member.status == ChatMemberStatus::Creator
                                        }
                                        Err(e) => {
                                            eprintln!(
                                                "Failed to fetch member info (not free plan limit, likely API response issue): {:?}",
                                                e
                                            );
                                            // NOTE: This is not a free plan limit.
                                            // If stronger consistency needed, consider using D1 instead of KV.
                                            false
                                        }
                                    }
                                };

                                if is_admin {
                                    self.log_spammer(reported_id, msg.chat.id.0, q.from.id.0)
                                        .await?;

                                    let _ = telegram::send_json_request(
                                        &self._token,
                                        AnswerCallbackQuery {
                                            callback_query_id: q.id.clone(),
                                            text: Some(
                                                "کاربر گزارش شد و به دیتابیس اسپمرها اضافه شد!"
                                                    .to_string(),
                                            ),
                                            url: None,
                                            cache_time: None,
                                            show_alert: Some(false),
                                        },
                                    )
                                    .await?;

                                    let _ = telegram::send_json_request(
                                        &self._token,
                                        DeleteMessage {
                                            chat_id: ChatTarget::Id(msg.chat.id),
                                            message_id: msg.message_id,
                                        },
                                    )
                                    .await;
                                } else {
                                    let _ = telegram::send_json_request(
                                        &self._token,
                                        AnswerCallbackQuery {
                                            callback_query_id: q.id.clone(),
                                            text: Some(
                                                "فقط ادمین‌های گروه می‌تونن گزارش بدن!".to_string(),
                                            ),
                                            show_alert: Some(true),
                                            url: None,
                                            cache_time: None,
                                        },
                                    )
                                    .await?;
                                }
                                return Response::empty();
                            }
                        }
                    }
                }
            }
            _ => {}
        }

        Response::empty()
    }
}

fn extract_question(text: &str) -> String {
    let lines: Vec<&str> = text.lines().collect();
    lines[lines.len() - 1].to_string()
}

fn extract_key_details(text: &str) -> (ChatId, MessageId) {
    let mut chat_id = 0;
    let mut message_id = 0;

    let info = text.strip_prefix(JOIN_PREFIX).unwrap();
    let info = info
        .split(':')
        .map(|x| x.parse().unwrap_or_default())
        .collect::<Vec<i64>>();

    if info.len() == 2 {
        chat_id = info[0];
        message_id = info[1];
    }

    (ChatId(chat_id), MessageId(message_id))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_question() {
        let question = extract_question("first line\nsecond line\nthird line");
        assert_eq!(question, "third line");
    }

    #[test]
    fn test_extract_key_details() {
        let (chat_id, message_id) = extract_key_details(&format!("{}{}:{}", JOIN_PREFIX, 123, 456));
        assert_eq!(chat_id.0, 123);
        assert_eq!(message_id.0, 456);

        let (chat_id, message_id) = extract_key_details(&format!("{}{}-", JOIN_PREFIX, 123));
        assert_eq!(chat_id.0, 0);
        assert_eq!(message_id.0, 0);
    }
}
