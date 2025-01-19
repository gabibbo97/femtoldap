use std::{collections::HashSet, str::FromStr, sync::Arc};

use futures::{SinkExt, StreamExt};
use metrics::counter;
use tracing::Level;

use crate::ldap::{attribute::LDAPAttribute, dn::LDAPDN};

use super::{database::LDAPReadOnlyInMemoryDatabase, entry::LDAPEntry};

#[derive(Debug, Default)]
pub enum BindStatus {
    #[default] Anonymous,
    Bound(Arc<LDAPEntry>),
}
impl BindStatus {
    pub fn unbind(&mut self) {
        *self = Self::Anonymous;
    }
}

pub struct ClientHandler<I> {
    bind_status: BindStatus,
    database: Arc<LDAPReadOnlyInMemoryDatabase>,
    addr: std::net::SocketAddr,
    io: tokio_util::codec::Framed<I, ldap3_proto::LdapCodec>,
}
impl<I> ClientHandler<I>
where
    I: tokio::io::AsyncRead + tokio::io::AsyncWrite + std::marker::Unpin
{
    pub fn new(conn: I, addr: std::net::SocketAddr, database: Arc<LDAPReadOnlyInMemoryDatabase>) -> Self {
        let codec = ldap3_proto::LdapCodec::new(Some(1 * 1024 * 1024));
        let io = tokio_util::codec::Framed::new(conn, codec);
        Self {
            bind_status: BindStatus::Anonymous,
            database,
            addr,
            io,
        }
    }

    pub async fn handle_connection(&mut self) -> anyhow::Result<()>
    {
        while let Some(msg) = self.io.next().await {
            match msg {
                Ok(message) => {
                    self.handle_message(message).await?;
                },
                Err(err) => {
                    tracing::error!(error = ?err);
                    break;
                }
            }
        }
        Ok(())
    }

    #[tracing::instrument(skip(self))]
    async fn handle_message(&mut self, msg: ldap3_proto::LdapMsg) -> anyhow::Result<()>
    {
        tracing::debug!("Handling");
        match msg.op {
            //
            // Bind
            //
            ldap3_proto::proto::LdapOp::BindRequest(request) => {
                // metrics
                counter!("femtoldap_requests_total", "kind" => "bind").increment(1);

                // grab dn out of the request
                let dn = LDAPDN::from_str(&request.dn)?;

                // grab password out of the request
                let password = match request.cred {
                    ldap3_proto::proto::LdapBindCred::Simple(password) => password,
                    ldap3_proto::proto::LdapBindCred::SASL(_) => {
                        self.io.send(ldap3_proto::LdapMsg { msgid: msg.msgid, op: ldap3_proto::proto::LdapOp::BindResponse(ldap3_proto::proto::LdapBindResponse::new_invalidcredentials(&request.dn, "SASL bind not supported")), ctrl: Vec::new() }).await?;
                        tracing::event!(Level::INFO, address = ?self.addr, dn = dn.to_string(), "Failed login: SASL bind not supported");
                        return Ok(())
                    },
                };

                // grab entry
                if let Some(bound_entry) = self.database.do_bind(&dn, password) {
                    // bind successful
                    tracing::event!(Level::INFO, address = ?self.addr, dn = dn.to_string(), "Login successful");
                    self.io.send(ldap3_proto::LdapMsg { msgid: msg.msgid, op: ldap3_proto::proto::LdapOp::BindResponse(ldap3_proto::proto::LdapBindResponse::new_success("")), ctrl: Vec::new() }).await?;
                    self.bind_status = BindStatus::Bound(bound_entry);
                    counter!("femtoldap_successful_binds_total").increment(1);
                } else {
                    // bind failed
                    tracing::event!(Level::INFO, address = ?self.addr, dn = dn.to_string(), "Login failed");
                    self.io.send(ldap3_proto::LdapMsg { msgid: msg.msgid, op: ldap3_proto::proto::LdapOp::BindResponse(ldap3_proto::proto::LdapBindResponse::new_invalidcredentials(&request.dn, "Bind failed")), ctrl: Vec::new() }).await?;
                    counter!("femtoldap_failed_binds_total").increment(1);
                }
            },
            ldap3_proto::proto::LdapOp::UnbindRequest => {
                // metrics
                counter!("femtoldap_requests_total", "kind" => "unbind").increment(1);

                self.bind_status.unbind();
            },
            //
            // Search
            //
            ldap3_proto::proto::LdapOp::SearchRequest(request) => {
                // metrics
                counter!("femtoldap_requests_total", "kind" => "search").increment(1);

                // grab dn out of the request
                let dn = LDAPDN::from_str(&request.base)?;

                // check access to base DN
                let can_access = dn.is_empty() || match &self.bind_status {
                    // do not allow anything as anonymous
                    BindStatus::Anonymous => false,
                    // allow to access base if entity is under it and may read itself
                    BindStatus::Bound(entry) if entry.acls.can_access_self && entry.dn.matches_suffix(&dn) => true,
                    // allow to access base if enabled
                    BindStatus::Bound(entry) => entry.acls.can_access_dn(&entry, &dn),
                };
                if ! can_access {
                    self.io.send(
                        ldap3_proto::LdapMsg {
                            msgid: msg.msgid,
                            op: ldap3_proto::proto::LdapOp::SearchResultDone(
                                ldap3_proto::proto::LdapResult {
                                    code: ldap3_proto::LdapResultCode::InappropriateAuthentication,
                                    matcheddn: request.base.clone(),
                                    message: "".into(),
                                    referral: Vec::new(),
                                }
                            ),
                            ctrl: Vec::new(),
                        }
                    ).await?;
                    return Ok(());
                }

                // do search
                let mut found_entries = self.database.search(&dn, &request.filter);

                // exclude entities on which we do not have authorization on
                found_entries.retain(|entry| match &self.bind_status {
                    // do not allow anything as anonymous
                    BindStatus::Anonymous => false,
                    // allow to access Root DSE
                    BindStatus::Bound(..) if entry.dn.is_empty() => true,
                    // check permissions
                    BindStatus::Bound(bind_entry) => bind_entry.acls.can_access_dn(&bind_entry, &entry.dn),
                });

                if found_entries.is_empty() {
                    // nothing found
                    self.io.send(ldap3_proto::LdapMsg { msgid: msg.msgid, op: ldap3_proto::proto::LdapOp::SearchResultDone(ldap3_proto::proto::LdapResult {
                        code: ldap3_proto::LdapResultCode::NoSuchObject,
                        matcheddn: request.base,
                        message: "".into(),
                        referral: Vec::new(),
                    }), ctrl: Vec::new() }).await?;
                } else {
                    // return entries
                    let requested_attrs: HashSet<_> = request.attrs.iter().map(|x| x.as_str()).collect();
                    for entry in found_entries {
                        // attributes
                        let attributes: Vec<_> = if request.attrs.is_empty() {
                            // return all attributes
                            entry.attributes.iter()
                                .map(LDAPAttribute::as_ldap3_protocol_attribute)
                                .collect()
                        } else {
                            // return selected attributes
                            entry.attributes.iter()
                                .filter(|attribute| requested_attrs.contains(attribute.name.as_str()))
                                .map(LDAPAttribute::as_ldap3_protocol_attribute)
                                .collect()
                        };

                        // dn
                        let dn = if entry.dn.is_empty() {
                            // special handling of root DSE
                            "".to_string()
                        } else {
                            entry.dn.to_string()
                        };

                        self.io.send(ldap3_proto::LdapMsg { msgid: msg.msgid, op: ldap3_proto::proto::LdapOp::SearchResultEntry(ldap3_proto::LdapSearchResultEntry { dn, attributes }), ctrl: Vec::new() }).await?;
                    }

                    // search success
                    self.io.send(ldap3_proto::LdapMsg { msgid: msg.msgid, op: ldap3_proto::proto::LdapOp::SearchResultDone(ldap3_proto::proto::LdapResult {
                        code: ldap3_proto::LdapResultCode::Success,
                        matcheddn: request.base,
                        message: "".into(),
                        referral: Vec::new(),
                    }), ctrl: Vec::new() }).await?;
                }
            },
            //
            // Unknown
            //
            operation => {
                // metrics
                counter!("femtoldap_requests_total", "kind" => "unsupported").increment(1);

                tracing::warn!(?operation, "Unsupported LDAP operation");
            }
        }
        Ok(())
    }
}
