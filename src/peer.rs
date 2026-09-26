use crate::common::*;
use crate::database;
use hbb_common::{
    bytes::Bytes,
    log,
    rendezvous_proto::*,
    tokio::sync::{Mutex, RwLock},
    ResultType,
};
use serde_derive::{Deserialize, Serialize};
use std::{collections::HashMap, collections::HashSet, net::SocketAddr, sync::Arc, time::Instant};

type IpBlockMap = HashMap<String, ((u32, Instant), (HashSet<String>, Instant))>;
type UserStatusMap = HashMap<Vec<u8>, Arc<(Option<Vec<u8>>, bool)>>;
type IpChangesMap = HashMap<String, (Instant, HashMap<String, i32>)>;
lazy_static::lazy_static! {
    pub(crate) static ref IP_BLOCKER: Mutex<IpBlockMap> = Default::default();
    pub(crate) static ref USER_STATUS: RwLock<UserStatusMap> = Default::default();
    pub(crate) static ref IP_CHANGES: Mutex<IpChangesMap> = Default::default();
}
pub const IP_CHANGE_DUR: u64 = 180;
pub const IP_CHANGE_DUR_X2: u64 = IP_CHANGE_DUR * 2;
pub const DAY_SECONDS: u64 = 3600 * 24;
pub const IP_BLOCK_DUR: u64 = 60;

#[derive(Debug, Default, Serialize, Deserialize, Clone)]
pub(crate) struct PeerInfo {
    #[serde(default)]
    pub(crate) ip: String,
}

pub(crate) struct Peer {
    pub(crate) socket_addr: SocketAddr,
    pub(crate) last_reg_time: Instant,
    pub(crate) guid: Vec<u8>,
    pub(crate) uuid: Bytes,
    pub(crate) pk: Bytes,
    // pub(crate) user: Option<Vec<u8>>,
    pub(crate) info: PeerInfo,
    // pub(crate) disabled: bool,
    pub(crate) reg_pk: (u32, Instant), // how often register_pk
}

impl Default for Peer {
    fn default() -> Self {
        Self {
            socket_addr: "0.0.0.0:0".parse().unwrap(),
            last_reg_time: get_expired_time(),
            guid: Vec::new(),
            uuid: Bytes::new(),
            pk: Bytes::new(),
            info: Default::default(),
            // user: None,
            // disabled: false,
            reg_pk: (0, get_expired_time()),
        }
    }
}

pub(crate) type LockPeer = Arc<RwLock<Peer>>;

#[derive(Clone)]
pub(crate) struct PeerMap {
    map: Arc<RwLock<HashMap<String, LockPeer>>>,
    pub(crate) db: database::Database,
}

impl PeerMap {
    pub(crate) async fn new() -> ResultType<Self> {
        let db = std::env::var("DB_URL").unwrap_or({
            let mut db = "db_v2.sqlite3".to_owned();
            #[cfg(all(windows, not(debug_assertions)))]
            {
                if let Some(path) = hbb_common::config::Config::icon_path().parent() {
                    db = format!("{}\\{}", path.to_str().unwrap_or("."), db);
                }
            }
            #[cfg(not(windows))]
            {
                db = format!("./{db}");
            }
            db
        });
        log::info!("DB_URL={}", db);
        let pm = Self {
            map: Default::default(),
            db: database::Database::new(&db).await?,
        };
        Ok(pm)
    }

    #[inline]
    pub(crate) async fn update_pk(
        &mut self,
        id: String,
        peer: LockPeer,
        addr: SocketAddr,
        uuid: Bytes,
        pk: Bytes,
        ip: String,
    ) -> register_pk_response::Result {
        log::info!("update_pk {} {:?} {:?} {:?}", id, addr, uuid, pk);
        let (info_str, guid) = {
            let mut w = peer.write().await;
            w.socket_addr = addr;
            w.uuid = uuid.clone();
            w.pk = pk.clone();
            w.last_reg_time = Instant::now();
            w.info.ip = ip;
            (
                serde_json::to_string(&w.info).unwrap_or_default(),
                w.guid.clone(),
            )
        };
        if guid.is_empty() {
            match self.db.insert_peer(&id, &uuid, &pk, &info_str).await {
                Err(err) => {
                    log::error!("db.insert_peer failed: {}", err);
                    return register_pk_response::Result::SERVER_ERROR;
                }
                Ok(guid) => {
                    peer.write().await.guid = guid;
                }
            }
        } else {
            if let Err(err) = self.db.update_pk(&guid, &id, &pk, &info_str).await {
                log::error!("db.update_pk failed: {}", err);
                return register_pk_response::Result::SERVER_ERROR;
            }
            log::info!("pk updated instead of insert");
        }
        register_pk_response::Result::OK
    }

    #[inline]
    pub(crate) async fn get(&self, id: &str) -> Option<LockPeer> {
        let p = self.map.read().await.get(id).cloned();
        if p.is_some() {
            return p;
        } else if let Ok(Some(v)) = self.db.get_peer(id).await {
            let peer = Peer {
                guid: v.guid,
                uuid: v.uuid.into(),
                pk: v.pk.into(),
                // user: v.user,
                info: serde_json::from_str::<PeerInfo>(&v.info).unwrap_or_default(),
                // disabled: v.status == Some(0),
                ..Default::default()
            };
            let peer = Arc::new(RwLock::new(peer));
            self.map.write().await.insert(id.to_owned(), peer.clone());
            return Some(peer);
        }
        None
    }

    #[inline]
    pub(crate) async fn get_or(&self, id: &str) -> LockPeer {
        if let Some(p) = self.get(id).await {
            return p;
        }
        let mut w = self.map.write().await;
        if let Some(p) = w.get(id) {
            return p.clone();
        }
        let tmp = LockPeer::default();
        w.insert(id.to_owned(), tmp.clone());
        tmp
    }

    #[inline]
    pub(crate) async fn get_in_memory(&self, id: &str) -> Option<LockPeer> {
        self.map.read().await.get(id).cloned()
    }

    #[inline]
    pub(crate) async fn is_in_memory(&self, id: &str) -> bool {
        self.map.read().await.contains_key(id)
    }

    /// Renames `old_id` to `new_id` for the client's "Change ID", keeping the peer's guid,
    /// key and info. Only the machine that registered `old_id` (same uuid) may rename it.
    pub(crate) async fn change_id(
        &self,
        old_id: &str,
        new_id: &str,
        uuid: &[u8],
    ) -> register_pk_response::Result {
        if !hbb_common::is_valid_custom_id(new_id) {
            return register_pk_response::Result::INVALID_ID_FORMAT;
        }
        let Some(peer) = self.get(old_id).await else {
            return register_pk_response::Result::UUID_MISMATCH;
        };
        let (guid, pk, info) = {
            let p = peer.read().await;
            if p.guid.is_empty() || p.uuid.as_ref() != uuid {
                return register_pk_response::Result::UUID_MISMATCH;
            }
            (
                p.guid.clone(),
                p.pk.clone(),
                serde_json::to_string(&p.info).unwrap_or_default(),
            )
        };
        if new_id == old_id {
            return register_pk_response::Result::OK;
        }
        // An in-memory entry without a guid is only a placeholder, not a registered peer.
        if let Some(existing) = self.get(new_id).await {
            if !existing.read().await.guid.is_empty() {
                return register_pk_response::Result::ID_EXISTS;
            }
        }
        if let Err(err) = self.db.update_pk(&guid, new_id, &pk, &info).await {
            log::error!("db.update_pk failed changing id {} to {}: {}", old_id, new_id, err);
            return register_pk_response::Result::SERVER_ERROR;
        }
        let mut map = self.map.write().await;
        map.remove(old_id);
        map.insert(new_id.to_owned(), peer);
        register_pk_response::Result::OK
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hbb_common::tokio;

    #[test]
    fn test_change_id() {
        change_id_cases();
    }

    #[tokio::main(flavor = "multi_thread")]
    async fn change_id_cases() {
        use register_pk_response::Result::*;
        let path = std::env::temp_dir().join(format!("hbbs-change-id-{}.sqlite3", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let pm = PeerMap {
            map: Default::default(),
            db: database::Database::new(path.to_str().unwrap()).await.unwrap(),
        };
        pm.db.insert_peer("123456789", b"uuid-a", b"pk-a", "{}").await.unwrap();
        pm.db.insert_peer("takenid1", b"uuid-b", b"pk-b", "{}").await.unwrap();

        assert_eq!(pm.change_id("123456789", "1bad", b"uuid-a").await, INVALID_ID_FORMAT);
        assert_eq!(pm.change_id("123456789", "newname1", b"uuid-x").await, UUID_MISMATCH);
        assert_eq!(pm.change_id("987654321", "newname1", b"uuid-a").await, UUID_MISMATCH);
        assert_eq!(pm.change_id("123456789", "takenid1", b"uuid-a").await, ID_EXISTS);
        assert_eq!(pm.change_id("123456789", "newname1", b"uuid-a").await, OK);

        let renamed = pm.db.get_peer("newname1").await.unwrap().unwrap();
        assert_eq!(renamed.pk, b"pk-a");
        assert_eq!(renamed.uuid, b"uuid-a");
        assert!(pm.db.get_peer("123456789").await.unwrap().is_none());
        assert!(pm.get_in_memory("123456789").await.is_none());
        assert!(pm.get_in_memory("newname1").await.is_some());
        // The old id is free again; the renamed peer cannot be renamed from a stale id.
        assert_eq!(pm.change_id("123456789", "another1", b"uuid-a").await, UUID_MISMATCH);
        let _ = std::fs::remove_file(&path);
    }
}
