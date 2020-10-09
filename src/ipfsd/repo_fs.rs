//import (
//	filestore "github.com/ipfs/go-filestore"
//	keystore "github.com/ipfs/go-ipfs/keystore"
//	ds "github.com/ipfs/go-datastore"
//	config "github.com/ipfs/go-ipfs-config"
//	ma "github.com/multiformats/go-multiaddr"
//)

/// Environment variable point to the ipfs-repo path.
pub fn default_root() -> path::Path {
    use std::env;

    let ipfs_path = env::var("IPFS_PATH").unwrap_or("./ipfs".to_string());

    let mut root = dirs::home_dir();
    root.push(ipfs_path);
    root.to_path()
}

pub fn loc_config(root: path::Path, file: Option<ffi::OsString>) -> path::Path {
    let file = file.unwrap_or("config".to_os_string());
    let loc: path::PathBuf = vec![root, file].iter().collect();
    loc.to_path()
}

pub fn loc_datastore(root: path::Path, sub_dir: Option<ffi::OsString>) -> path::Path {
    let sub_dir = sub_dir.unwrap_or("datastore".to_os_string());
    let loc: path::PathBuf = vec![root, file].iter().collect();
    loc.to_path()
}

// Repo represents all persistent data of a given ipfs node.
struct FileRepo {
    config: Config,
}

impl FileRepo {
    /// Returns the ipfs configuration file from the repo. Changes made
    /// to the returned config are not automatically persisted.
    fn to_config() -> Result<Config> {
        todo!()
    }

    /// BackupConfig creates a backup of the current configuration file using
    /// the given prefix for naming.
    BackupConfig(prefix string) (string, error)

    // SetConfig persists the given configuration struct to storage.
    SetConfig(*config.Config) error

    // SetConfigKey sets the given key-value pair within the config and persists it to storage.
    SetConfigKey(key string, value interface{}) error

    // GetConfigKey reads the value for the given key from the configuration in storage.
    GetConfigKey(key string) (interface{}, error)

    // Datastore returns a reference to the configured data storage backend.
    Datastore() Datastore

    // GetStorageUsage returns the number of bytes stored.
    GetStorageUsage() (uint64, error)

    // Keystore returns a reference to the key management interface.
    Keystore() keystore.Keystore

    // FileManager returns a reference to the filestore file manager.
    FileManager() *filestore.FileManager

    // SetAPIAddr sets the API address in the repo.
    SetAPIAddr(addr ma.Multiaddr) error

    // SwarmKey returns the configured shared symmetric key for the private networks feature.
    SwarmKey() ([]byte, error)

    close
}

// Datastore is the interface required from a datastore to be
// acceptable to FSRepo.
type Datastore interface {
	ds.Batching // must be thread-safe
}


