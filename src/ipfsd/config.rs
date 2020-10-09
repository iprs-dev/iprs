// TODO: HumanOutput for config value ready for pretty printing,
// in json format.

/// Inter-Planetary file system configuration.
#[derive(Clone)]
pub struct Config {
    identity: Identity,     // local node's peer identity
    datastore: Datastore,   // local node's storage
    addrs: Addresses,       // local node's addresses
    mounts: Mounts,         // local node's mount points
    discovery: Discovery,   // local node's discovery mechanisms
    routing: Routing,       // local node's routing settings
    ipns: Ipns,             // Ipns settings
    bootstrap: Vec<String>, // local nodes's bootstrap peer addresses
    gateway: Gateway,       // local node's gateway server options
    api: API,               // local node's API settings
    swarm: Swarm,
    auto_nat: AutoNAT,
    pubsub: PubsubConfig,
    peering: Peering,

    provider: Provider,
    reprovider: Reprovider,
    experimental: Experiments,
    plugins: Plugins,
}

/// Configuration of local node's identity.
pub struct Identity {
    peer_id: String,
    priv_key: Option<String>,
    // `priv_key` shall be decoded into `key_pair`, we might also
    // add other ways of picking up the key_pair, other than from
    // config file, i.e `priv_key`.
    key_pair: Option<identity::KeyPair>,
}

// Datastore tracks the configuration of the datastore.
pub struct Datastore {
    storage_max: String,       // in B, kB, kiB, MB, ...
    storage_gc_watermark: u64, // in percentage to multiply on StorageMax
    gc_period: String,         // in ns, us, ms, s, m, h
    spec: toml::Value,
    hash_on_read: bool,
    bloom_filtersize: usizea,
}

// Addresses stores the (string) multiaddr addresses for the node.
pub struct Addresses {
    swarm: Vec<String>,       // addresses for the swarm to listen on
    announce: Vec<String>,    // swarm addresses to announce to the network
    no_announce: Vec<String>, // swarm addresses not to announce to the network
    api: Vec<String>,         // address for the local API (RPC)
    gateway: Vec<String>,     // address to listen on for IPFS HTTP object gateway
}

// Mounts stores the (string) mount points
pub struct Mounts {
    ipfs: String,
    ipns: String,
    fuse_allow_other: bool,
}

pub struct Discovery {
    mdns: Mdns,
}

pub struct Mdns {
    enabled: bool,
    interval: u64, // Time in seconds between discovery rounds
}

// Routing defines configuration options for libp2p routing
pub struct Routing {
    // Type sets default daemon routing mode.
    // Can be one of "dht", "dhtclient", "dhtserver", "none", or unset.
    r#type: String,
}

pub struct Ipns {
    republish_period: String,
    record_lifetime: String,
    resolve_cachesize: usize,
}

pub struct GatewaySpec {
    // Paths is explicit list of path prefixes that should be handled by
    // this gateway. Example: `["/ipfs", "/ipns", "/api"]`
    paths: Vec<String>,
    // UseSubdomains indicates whether or not this gateway uses subdomains
    // for IPFS resources instead of paths. That is: http://CID.ipfs.GATEWAY/...
    //
    // If this flag is set, any /ipns/$id and/or /ipfs/$id paths in PathPrefixes
    // will be permanently redirected to http://$id.[ipns|ipfs].$gateway/.
    //
    // We do not support using both paths and subdomains for a single domain
    // for security reasons (Origin isolation).
    use_subdomains: bool,
    // NoDNSLink configures this gateway to _not_ resolve DNSLink for the FQDN
    // provided in `Host` HTTP header.
    no_dnslink: bool,
}

// Gateway contains options for the HTTP gateway server.
pub struct Gateway {
    // HTTPHeaders configures the headers that should be returned by this
    // gateway.
    http_headers: toml::Value, // HTTP headers to return with the gateway
    // RootRedirect is the path to which requests to `/` on this gateway
    // should be redirected.
    root_redirect: String,
    // Writable enables PUT/POST request handling by this gateway. Usually,
    // writing is done through the API, not the gateway.
    writable: bool,
    // PathPrefixes  is an array of acceptable url paths that a client can
    // specify in X-Ipfs-Path-Prefix header.
    //
    // The X-Ipfs-Path-Prefix header is used to specify a base path to prepend
    // to links in directory listings and for trailing-slash redirects. It is
    // intended to be set by a frontend http proxy like nginx.
    //
    // Example: To mount blog.ipfs.io (a DNSLink site) at ipfs.io/blog
    // set PathPrefixes to ["/blog"] and nginx config to translate paths
    // and pass Host header (for DNSLink):
    //  location /blog/ {
    //    rewrite "^/blog(/.*)$" $1 break;
    //    proxy_set_header Host blog.ipfs.io;
    //    proxy_set_header X-Ipfs-Gateway-Prefix /blog;
    //    proxy_pass http://127.0.0.1:8080;
    //  }
    path_prefixes: Vec<String>,
    // FIXME: Not yet implemented
    api_commands: Vec<String>,
    // NoFetch configures the gateway to _not_ fetch blocks in response to
    // requests.
    no_fetch: bool,
    // NoDNSLink configures the gateway to _not_ perform DNS TXT record
    // lookups in response to requests with values in `Host` HTTP header.
    // This flag can be overriden per FQDN in PublicGateways.
    no_dnslink: bool,
    // PublicGateways configures behavior of known public gateways.
    // Each key is a fully qualified domain name (FQDN).
    public_gateways: toml::Value,
}

pub struct Api {
    http_headers: toml::Value, // HTTP headers to return with the API.
}

pub struct Swarm {
    // AddrFilters specifies a set libp2p addresses that we should never
    // dial or receive connections from.
    addr_filters: Vec<String>,
    // DisableBandwidthMetrics disables recording of bandwidth metrics for a
    // slight reduction in memory usage. You probably don't need to set this
    // flag.
    disable_bandwidth_metrics: bool,
    // DisableNatPortMap turns off NAT port mapping (UPnP, etc.).
    disable_nat_portmap: bool,
    // EnableRelayHop makes this node act as a public relay, relaying
    // traffic between other nodes.
    enable_relay_hop: bool,
    // EnableAutoRelay enables the "auto relay" feature.
    //
    // When both EnableAutoRelay and EnableRelayHop are set, this go-ipfs node
    // will advertise itself as a public relay. Otherwise it will find and use
    // advertised public relays when it determines that it's not reachable
    // from the public internet.
    enable_auto_relay: bool,
    // Transports contains flags to enable/disable libp2p transports.
    transports: Transports,
    // ConnMgr configures the connection manager.
    connmgr: ConnMgr,
}

pub struct Transports {
    // Network specifies the base transports we'll use for dialing. To
    // listen on a transport, add the transport to your Addresses.Swarm.
    network: Network,
    // Security specifies the transports used to encrypt insecure network
    // transports.
    security: Security,
    // Multiplexers specifies the transports used to multiplex multiple
    // connections over a single duplex connection.
    multiplexers: Multiplexers,
}

pub struct Security {
    tls: Priority,   // Defaults to 100.
    secio: Priority, // Defaults to 200.
    noise: Priority, // Defaults to 300.
}
pub struct Network {
    quic: Ternary,
    tcp: Ternary,
    web_socket: Ternary,
    relay: Ternary,
}
pub struct Multiplexers {
    yamux: Priority, // Defaults to 100.
    mplex: Priority, // Defaults to 200.
}

// ConnMgr defines configuration options for the libp2p connection manager
pub struct ConnMgr {
    r#type: String,
    low_water: i64,
    high_water: i64,
    grace_period: String,
}

// AutoNAT configures the node's AutoNAT subsystem.
pub struct AutoNAT {
    // Service configures the node's AutoNAT service mode.
    service: AutoNATService,

    // Throttle configures AutoNAT dialback throttling.
    //
    // If unset, the conservative libp2p defaults will be unset. To help the
    // network, please consider setting this and increasing the limits.
    //
    // By default, the limits will be a total of 30 dialbacks, with a
    // per-peer max of 3 peer, resetting every minute.
    throttle AutoNATThrottle,
}

// AutoNATThrottleConfig configures the throttle limites
pub struct AutoNATThrottle {
    // GlobalLimit and PeerLimit sets the global and per-peer dialback
    // limits. The AutoNAT service will only perform the specified number of
    // dialbacks per interval.
    //
    // Setting either to 0 will disable the appropriate limit.
    global_limit: u64,
    peer_limit: u64,
    // Interval specifies how frequently this node should reset the
    // global/peer dialback limits.
    //
    // When unset, this defaults to 1 minute.
    interval: u64,
}

enum AutoNATService {
    // Unset indicates that the user has not set the AutoNATService mode.
    //
    // When unset, nodes configured to be public DHT nodes will _also_
    // perform limited AutoNAT dialbacks.
    Unset,
    // Enabled indicates that the user has enabled the AutoNATService.
    Enabled
    // Disabled indicates that the user has disabled the AutoNATService.
    Disabled
)

impl Config {
    pub fn to_peer_id(&self) -> PeerId {
        todo!()
    }
}
