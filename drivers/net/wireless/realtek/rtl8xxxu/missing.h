#if LINUX_VERSION_CODE > KERNEL_VERSION(4,8,17)
#include <linux/bitfield.h>
#endif
#include <linux/list.h>
#include <net/mac80211.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/errno.h>
#include <linux/slab.h>
#include <linux/module.h>
#include <linux/spinlock.h>
#include <linux/list.h>
#include <linux/usb.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/ethtool.h>
#include <linux/wireless.h>
#include <linux/firmware.h>
#include <linux/moduleparam.h>
#include <net/mac80211.h>
#include <asm/byteorder.h>
#if LINUX_VERSION_CODE <= KERNEL_VERSION(3,5,7)
#define ETH_ALEN	6
static inline void eth_broadcast_addr(u8 *addr)
{
	memset(addr, 0xff, ETH_ALEN);
}
#endif
#if LINUX_VERSION_CODE <= KERNEL_VERSION(3,13,11)
static inline void ether_addr_copy(u8 *dst, const u8 *src)
{
	u16 *a = (u16 *)dst;
	const u16 *b = (const u16 *)src;

	a[0] = b[0];
	a[1] = b[1];
	a[2] = b[2];
}
#endif
#if LINUX_VERSION_CODE <= KERNEL_VERSION(3,7,10)
#define IEEE80211_NUM_TIDS 16
	#if LINUX_VERSION_CODE <= KERNEL_VERSION(3,5,0)
static inline bool ether_addr_equal(const u8 *addr1, const u8 *addr2)
{
		#if defined(CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS)
	u32 fold = ((*(const u32 *)addr1) ^ (*(const u32 *)addr2)) |
		   ((*(const u16 *)(addr1 + 4)) ^ (*(const u16 *)(addr2 + 4)));

	return fold == 0;
		#else
	const u16 *a = (const u16 *)addr1;
	const u16 *b = (const u16 *)addr2;

	return ((a[0] ^ b[0]) | (a[1] ^ b[1]) | (a[2] ^ b[2])) == 0;
		#endif
}
	#endif 3-5-0
#endif 3-7-10
#if LINUX_VERSION_CODE <= KERNEL_VERSION(3,9,11)
#define list_first_entry_or_null(ptr, type, member) ({ \
	struct list_head *head__ = (ptr); \
	struct list_head *pos__ = ACCESS_ONCE(head__->next); \
	pos__ != head__ ? list_entry(pos__, type, member) : NULL; \
})
#define IEEE80211_SCTL_SEQ		0xFFF0
#define IEEE80211_SEQ_TO_SN(seq)	(((seq) & IEEE80211_SCTL_SEQ) >> 4)
#endif
#if LINUX_VERSION_CODE <= KERNEL_VERSION(4,15,18)
static __always_inline u64 field_multiplier(u64 field)
{
	return field & -field;
}
static __always_inline u64 field_mask(u64 field)
{
	return field / field_multiplier(field);
}
#define ____MAKE_OP(type,base,to,from)					\
static __always_inline __##type type##_encode_bits(base v, base field)	\
{									\
	return to((v & field_mask(field)) * field_multiplier(field));	\
}									\
static __always_inline __##type type##_replace_bits(__##type old,	\
					base val, base field)		\
{									\
	return (old & ~to(field)) | type##_encode_bits(val, field);	\
}									\
static __always_inline void type##p_replace_bits(__##type *p,		\
					base val, base field)		\
{									\
	*p = (*p & ~to(field)) | type##_encode_bits(val, field);	\
}									\
static __always_inline base type##_get_bits(__##type v, base field)	\
{									\
	return (from(v) & field)/field_multiplier(field);		\
}
#define __MAKE_OP(size)							\
	____MAKE_OP(le##size,u##size,cpu_to_le##size,le##size##_to_cpu)	\
	____MAKE_OP(be##size,u##size,cpu_to_be##size,be##size##_to_cpu)	\
	____MAKE_OP(u##size,u##size,,)
____MAKE_OP(u8,u8,,)
__MAKE_OP(16)
__MAKE_OP(32)
__MAKE_OP(64)
#undef __MAKE_OP
#undef ____MAKE_OP
#endif
#if LINUX_VERSION_CODE <= KERNEL_VERSION(3,12,74)
#define BIT_ULL(nr)		(1ULL << (nr))
#define GENMASK_INPUT_CHECK(h, l) 0
#define __GENMASK(h, l) \
	(((~UL(0)) - (UL(1) << (l)) + 1) & \
	 (~UL(0) >> (BITS_PER_LONG - 1 - (h))))
#define GENMASK(h, l) \
	(GENMASK_INPUT_CHECK(h, l) + __GENMASK(h, l))
#endif
#if LINUX_VERSION_CODE <= KERNEL_VERSION(4,8,17)
#define __bf_shf(x) (__builtin_ffsll(x) - 1)
#define __scalar_type_to_unsigned_cases(type)				\
		unsigned type:	(unsigned type)0,			\
		signed type:	(unsigned type)0
#define __unsigned_scalar_typeof(x) typeof(				\
		_Generic((x),						\
			char:	(unsigned char)0,			\
			__scalar_type_to_unsigned_cases(char),		\
			__scalar_type_to_unsigned_cases(short),		\
			__scalar_type_to_unsigned_cases(int),		\
			__scalar_type_to_unsigned_cases(long),		\
			__scalar_type_to_unsigned_cases(long long),	\
			default: (x)))
#define FIELD_MAX(_mask)						\
	({								\
		(typeof(_mask))((_mask) >> __bf_shf(_mask));		\
	})
#define FIELD_FIT(_mask, _val)						\
	({								\
		!((((typeof(_mask))_val) << __bf_shf(_mask)) & ~(_mask)); \
	})
#define FIELD_PREP(_mask, _val)						\
	({								\
		((typeof(_mask))(_val) << __bf_shf(_mask)) & (_mask);	\
	})
#define FIELD_GET(_mask, _reg)						\
	({								\
		(typeof(_mask))(((_reg) & (_mask)) >> __bf_shf(_mask));	\
	})
#endif
#if LINUX_VERSION_CODE <= KERNEL_VERSION(3,4,113)
struct mesh_preq_queue {
	struct list_head list;
	u8 dst[ETH_ALEN];
	u8 flags;
};
struct ieee80211_if_ibss {
	struct timer_list timer;

	struct mutex mtx;

	unsigned long last_scan_completed;

	u32 basic_rates;

	bool timer_running;

	bool fixed_bssid;
	bool fixed_channel;
	bool privacy;

	bool control_port;

	u8 bssid[ETH_ALEN] __aligned(2);
	u8 ssid[IEEE80211_MAX_SSID_LEN];
	u8 ssid_len, ie_len;
	u8 *ie;
	struct ieee80211_channel *channel;
	enum nl80211_channel_type channel_type;

	unsigned long ibss_join_req;
	/* probe response/beacon for IBSS */
	struct sk_buff __rcu *presp;
	struct sk_buff *skb;

	spinlock_t incomplete_lock;
	struct list_head incomplete_stations;

	enum {
		IEEE80211_IBSS_MLME_SEARCH,
		IEEE80211_IBSS_MLME_JOINED,
	} state;
};
enum mac80211_scan_state {
	SCAN_DECISION,
	SCAN_SET_CHANNEL,
	SCAN_SEND_PROBE,
	SCAN_SUSPEND,
	SCAN_RESUME,
};
enum ieee80211_internal_tkip_state {
	TKIP_STATE_NOT_INIT,
	TKIP_STATE_PHASE1_DONE,
	TKIP_STATE_PHASE1_HW_UPLOADED,
};
struct tkip_ctx {
	u32 iv32;	/* current iv32 */
	u16 iv16;	/* current iv16 */
	u16 p1k[5];	/* p1k cache */
	u32 p1k_iv32;	/* iv32 for which p1k computed */
	enum ieee80211_internal_tkip_state state;
};
struct mesh_stats {
	__u32 fwded_mcast;		/* Mesh forwarded multicast frames */
	__u32 fwded_unicast;		/* Mesh forwarded unicast frames */
	__u32 fwded_frames;		/* Mesh total forwarded frames */
	__u32 dropped_frames_ttl;	/* Not transmitted since mesh_ttl == 0*/
	__u32 dropped_frames_no_route;	/* Not transmitted, no route found */
	__u32 dropped_frames_congestion;/* Not forwarded due to congestion */
	atomic_t estab_plinks;
};
struct ieee80211_if_mesh {
	struct timer_list housekeeping_timer;
	struct timer_list mesh_path_timer;
	struct timer_list mesh_path_root_timer;

	unsigned long timers_running;

	unsigned long wrkq_flags;

	u8 mesh_id[IEEE80211_MAX_MESH_ID_LEN];
	size_t mesh_id_len;
	/* Active Path Selection Protocol Identifier */
	u8 mesh_pp_id;
	/* Active Path Selection Metric Identifier */
	u8 mesh_pm_id;
	/* Congestion Control Mode Identifier */
	u8 mesh_cc_id;
	/* Synchronization Protocol Identifier */
	u8 mesh_sp_id;
	/* Authentication Protocol Identifier */
	u8 mesh_auth_id;
	/* Local mesh Sequence Number */
	u32 sn;
	/* Last used PREQ ID */
	u32 preq_id;
	atomic_t mpaths;
	/* Timestamp of last SN update */
	unsigned long last_sn_update;
	/* Time when it's ok to send next PERR */
	unsigned long next_perr;
	/* Timestamp of last PREQ sent */
	unsigned long last_preq;
	struct mesh_rmc *rmc;
	spinlock_t mesh_preq_queue_lock;
	struct mesh_preq_queue preq_queue;
	int preq_queue_len;
	struct mesh_stats mshstats;
	struct mesh_config mshcfg;
	u32 mesh_seqnum;
	bool accepting_plinks;
	int num_gates;
	const u8 *ie;
	u8 ie_len;
	enum {
		IEEE80211_MESH_SEC_NONE = 0x0,
		IEEE80211_MESH_SEC_AUTHED = 0x1,
		IEEE80211_MESH_SEC_SECURED = 0x2,
	} security;
};
struct ieee80211_fragment_entry {
	unsigned long first_frag_time;
	unsigned int seq;
	unsigned int rx_queue;
	unsigned int last_frag;
	unsigned int extra_len;
	struct sk_buff_head skb_list;
	int ccmp; /* Whether fragments were encrypted with CCMP */
	u8 last_pn[6]; /* PN of the last fragment if CCMP was used */
};
struct ieee80211_if_wds {
	struct sta_info *sta;
	u8 remote_addr[ETH_ALEN];
};
struct ieee80211_if_vlan {
	struct list_head list;

	/* used for all tx if the VLAN is configured to 4-addr mode */
	struct sta_info __rcu *sta;
};
struct ieee80211_if_ap {
	struct beacon_data __rcu *beacon;
	struct sk_buff __rcu *probe_resp;

	struct list_head vlans;

	/* yes, this looks ugly, but guarantees that we can later use
	 * bitmap_empty :)
	 * NB: don't touch this bitmap, use sta_info_{set,clear}_tim_bit */
	u8 tim[sizeof(unsigned long) * BITS_TO_LONGS(IEEE80211_MAX_AID + 1)];
	struct sk_buff_head ps_bc_buf;
	atomic_t num_sta_ps; /* number of stations in PS mode */
	atomic_t num_sta_authorized; /* number of authorized stations */
	int dtim_count;
	bool dtim_bc_mc;
};
struct ieee80211_mgd_auth_data {
	struct cfg80211_bss *bss;
	unsigned long timeout;
	int tries;
	u16 algorithm, expected_transaction;

	u8 key[WLAN_KEY_LEN_WEP104];
	u8 key_len, key_idx;
	bool done;

	size_t ie_len;
	u8 ie[];
};
struct ieee80211_local {
	/* embed the driver visible part.
	 * don't cast (use the static inlines below), but we keep
	 * it first anyway so they become a no-op */
	struct ieee80211_hw hw;

	const struct ieee80211_ops *ops;

	/*
	 * work stuff, potentially off-channel (in the future)
	 */
	struct list_head work_list;
	struct timer_list work_timer;
	struct work_struct work_work;

	/*
	 * private workqueue to mac80211. mac80211 makes this accessible
	 * via ieee80211_queue_work()
	 */
	struct workqueue_struct *workqueue;

	unsigned long queue_stop_reasons[IEEE80211_MAX_QUEUES];
	/* also used to protect ampdu_ac_queue and amdpu_ac_stop_refcnt */
	spinlock_t queue_stop_reason_lock;

	int open_count;
	int monitors, cooked_mntrs;
	/* number of interfaces with corresponding FIF_ flags */
	int fif_fcsfail, fif_plcpfail, fif_control, fif_other_bss, fif_pspoll,
	    fif_probe_req;
	int probe_req_reg;
	unsigned int filter_flags; /* FIF_* */

	bool wiphy_ciphers_allocated;

	/* protects the aggregated multicast list and filter calls */
	spinlock_t filter_lock;

	/* used for uploading changed mc list */
	struct work_struct reconfig_filter;

	/* used to reconfigure hardware SM PS */
	struct work_struct recalc_smps;

	/* aggregated multicast list */
	struct netdev_hw_addr_list mc_list;

	bool tim_in_locked_section; /* see ieee80211_beacon_get() */

	/*
	 * suspended is true if we finished all the suspend _and_ we have
	 * not yet come up from resume. This is to be used by mac80211
	 * to ensure driver sanity during suspend and mac80211's own
	 * sanity. It can eventually be used for WoW as well.
	 */
	bool suspended;

	/*
	 * Resuming is true while suspended, but when we're reprogramming the
	 * hardware -- at that time it's allowed to use ieee80211_queue_work()
	 * again even though some other parts of the stack are still suspended
	 * and we still drop received frames to avoid waking the stack.
	 */
	bool resuming;

	/*
	 * quiescing is true during the suspend process _only_ to
	 * ease timer cancelling etc.
	 */
	bool quiescing;

	/* device is started */
	bool started;

	/* wowlan is enabled -- don't reconfig on resume */
	bool wowlan;

	int tx_headroom; /* required headroom for hardware/radiotap */

	/* Tasklet and skb queue to process calls from IRQ mode. All frames
	 * added to skb_queue will be processed, but frames in
	 * skb_queue_unreliable may be dropped if the total length of these
	 * queues increases over the limit. */
#define IEEE80211_IRQSAFE_QUEUE_LIMIT 128
	struct tasklet_struct tasklet;
	struct sk_buff_head skb_queue;
	struct sk_buff_head skb_queue_unreliable;

	/*
	 * Internal FIFO queue which is shared between multiple rx path
	 * stages. Its main task is to provide a serialization mechanism,
	 * so all rx handlers can enjoy having exclusive access to their
	 * private data structures.
	 */
	struct sk_buff_head rx_skb_queue;
	bool running_rx_handler;	/* protected by rx_skb_queue.lock */

	/* Station data */
	/*
	 * The mutex only protects the list, hash table and
	 * counter, reads are done with RCU.
	 */
	struct mutex sta_mtx;
	spinlock_t tim_lock;
	unsigned long num_sta;
	struct list_head sta_list;
	struct sta_info __rcu *sta_hash[256];
	struct timer_list sta_cleanup;
	int sta_generation;

	struct sk_buff_head pending[IEEE80211_MAX_QUEUES];
	struct tasklet_struct tx_pending_tasklet;

	atomic_t agg_queue_stop[IEEE80211_MAX_QUEUES];

	/* number of interfaces with corresponding IFF_ flags */
	atomic_t iff_allmultis, iff_promiscs;

	struct rate_control_ref *rate_ctrl;

	struct crypto_cipher *wep_tx_tfm;
	struct crypto_cipher *wep_rx_tfm;
	u32 wep_iv;

	/* see iface.c */
	struct list_head interfaces;
	struct mutex iflist_mtx;

	/*
	 * Key mutex, protects sdata's key_list and sta_info's
	 * key pointers (write access, they're RCU.)
	 */
	struct mutex key_mtx;

	/* mutex for scan and work locking */
	struct mutex mtx;

	/* Scanning and BSS list */
	unsigned long scanning;
	struct cfg80211_ssid scan_ssid;
	struct cfg80211_scan_request *int_scan_req;
	struct cfg80211_scan_request *scan_req, *hw_scan_req;
	struct ieee80211_channel *scan_channel;
	enum ieee80211_band hw_scan_band;
	int scan_channel_idx;
	int scan_ies_len;

	bool sched_scanning;
	struct ieee80211_sched_scan_ies sched_scan_ies;
	struct work_struct sched_scan_stopped_work;

	unsigned long leave_oper_channel_time;
	enum mac80211_scan_state next_scan_state;
	struct delayed_work scan_work;
	struct ieee80211_sub_if_data *scan_sdata;
	enum nl80211_channel_type _oper_channel_type;
	struct ieee80211_channel *oper_channel, *csa_channel;

	/* Temporary remain-on-channel for off-channel operations */
	struct ieee80211_channel *tmp_channel;
	enum nl80211_channel_type tmp_channel_type;

	/* SNMP counters */
	/* dot11CountersTable */
	u32 dot11TransmittedFragmentCount;
	u32 dot11MulticastTransmittedFrameCount;
	u32 dot11FailedCount;
	u32 dot11RetryCount;
	u32 dot11MultipleRetryCount;
	u32 dot11FrameDuplicateCount;
	u32 dot11ReceivedFragmentCount;
	u32 dot11MulticastReceivedFrameCount;
	u32 dot11TransmittedFrameCount;

#ifdef CONFIG_MAC80211_LEDS
	int tx_led_counter, rx_led_counter;
	struct led_trigger *tx_led, *rx_led, *assoc_led, *radio_led;
	struct tpt_led_trigger *tpt_led_trigger;
	char tx_led_name[32], rx_led_name[32],
	     assoc_led_name[32], radio_led_name[32];
#endif

#ifdef CONFIG_MAC80211_DEBUG_COUNTERS
	/* TX/RX handler statistics */
	unsigned int tx_handlers_drop;
	unsigned int tx_handlers_queued;
	unsigned int tx_handlers_drop_unencrypted;
	unsigned int tx_handlers_drop_fragment;
	unsigned int tx_handlers_drop_wep;
	unsigned int tx_handlers_drop_not_assoc;
	unsigned int tx_handlers_drop_unauth_port;
	unsigned int rx_handlers_drop;
	unsigned int rx_handlers_queued;
	unsigned int rx_handlers_drop_nullfunc;
	unsigned int rx_handlers_drop_defrag;
	unsigned int rx_handlers_drop_short;
	unsigned int rx_handlers_drop_passive_scan;
	unsigned int tx_expand_skb_head;
	unsigned int tx_expand_skb_head_cloned;
	unsigned int rx_expand_skb_head;
	unsigned int rx_expand_skb_head2;
	unsigned int rx_handlers_fragments;
	unsigned int tx_status_drop;
#define I802_DEBUG_INC(c) (c)++
#else /* CONFIG_MAC80211_DEBUG_COUNTERS */
#define I802_DEBUG_INC(c) do { } while (0)
#endif /* CONFIG_MAC80211_DEBUG_COUNTERS */


	int total_ps_buffered; /* total number of all buffered unicast and
				* multicast packets for power saving stations
				*/
	unsigned int wmm_acm; /* bit field of ACM bits (BIT(802.1D tag)) */

	bool pspolling;
	bool offchannel_ps_enabled;
	/*
	 * PS can only be enabled when we have exactly one managed
	 * interface (and monitors) in PS, this then points there.
	 */
	struct ieee80211_sub_if_data *ps_sdata;
	struct work_struct dynamic_ps_enable_work;
	struct work_struct dynamic_ps_disable_work;
	struct timer_list dynamic_ps_timer;
	struct notifier_block network_latency_notifier;
	struct notifier_block ifa_notifier;

	/*
	 * The dynamic ps timeout configured from user space via WEXT -
	 * this will override whatever chosen by mac80211 internally.
	 */
	int dynamic_ps_forced_timeout;
	int dynamic_ps_user_timeout;
	bool disable_dynamic_ps;

	int user_power_level; /* in dBm */
	int power_constr_level; /* in dBm */

	enum ieee80211_smps_mode smps_mode;

	struct work_struct restart_work;

#ifdef CONFIG_MAC80211_DEBUGFS
	struct local_debugfsdentries {
		struct dentry *rcdir;
		struct dentry *keys;
	} debugfs;
#endif

	struct ieee80211_channel *hw_roc_channel;
	struct net_device *hw_roc_dev;
	struct sk_buff *hw_roc_skb, *hw_roc_skb_for_status;
	struct work_struct hw_roc_start, hw_roc_done;
	enum nl80211_channel_type hw_roc_channel_type;
	unsigned int hw_roc_duration;
	u32 hw_roc_cookie;
	bool hw_roc_for_tx;

	struct idr ack_status_frames;
	spinlock_t ack_status_lock;

	/* dummy netdev for use w/ NAPI */
	struct net_device napi_dev;

	struct napi_struct napi;
};
struct ieee80211_key {
	struct ieee80211_local *local;
	struct ieee80211_sub_if_data *sdata;
	struct sta_info *sta;

	/* for sdata list */
	struct list_head list;

	/* protected by key mutex */
	unsigned int flags;

	union {
		struct {
			/* protects tx context */
			spinlock_t txlock;

			/* last used TSC */
			struct tkip_ctx tx;

			/* last received RSC */
			struct tkip_ctx rx[16];
		} tkip;
		struct {
			atomic64_t tx_pn;
			/*
			 * Last received packet number. The first
			 * NUM_RX_DATA_QUEUES counters are used with Data
			 * frames and the last counter is used with Robust
			 * Management frames.
			 */
			u8 rx_pn[16 + 1][6];
			struct crypto_cipher *tfm;
			u32 replays; /* dot11RSNAStatsCCMPReplays */
		} ccmp;
		struct {
			atomic64_t tx_pn;
			u8 rx_pn[6];
			struct crypto_cipher *tfm;
			u32 replays; /* dot11RSNAStatsCMACReplays */
			u32 icverrors; /* dot11RSNAStatsCMACICVErrors */
		} aes_cmac;
	} u;

	/* number of times this key has been used */
	int tx_rx_count;

#ifdef CONFIG_MAC80211_DEBUGFS
	struct {
		struct dentry *stalink;
		struct dentry *dir;
		int cnt;
	} debugfs;
#endif

	/*
	 * key config, must be last because it contains key
	 * material as variable length member
	 */
	struct ieee80211_key_conf conf;
};
struct ieee80211_mgd_assoc_data {
	struct cfg80211_bss *bss;
	const u8 *supp_rates;
	const u8 *ht_information_ie;

	unsigned long timeout;
	int tries;

	u16 capability;
	u8 prev_bssid[ETH_ALEN];
	u8 ssid[IEEE80211_MAX_SSID_LEN];
	u8 ssid_len;
	u8 supp_rates_len;
	bool wmm, uapsd;
	bool have_beacon;
	bool sent_assoc;
	bool synced;

	size_t ie_len;
	u8 ie[];
};
struct ieee80211_if_managed {
	struct timer_list timer;
	struct timer_list conn_mon_timer;
	struct timer_list bcn_mon_timer;
	struct timer_list chswitch_timer;
	struct work_struct monitor_work;
	struct work_struct chswitch_work;
	struct work_struct beacon_connection_loss_work;

	unsigned long beacon_timeout;
	unsigned long probe_timeout;
	int probe_send_count;
	bool nullfunc_failed;

	struct mutex mtx;
	struct cfg80211_bss *associated;
	struct ieee80211_mgd_auth_data *auth_data;
	struct ieee80211_mgd_assoc_data *assoc_data;

	u8 bssid[ETH_ALEN];

	u16 aid;

	unsigned long timers_running; /* used for quiesce/restart */
	bool powersave; /* powersave requested for this iface */
	bool broken_ap; /* AP is broken -- turn off powersave */
	enum ieee80211_smps_mode req_smps, /* requested smps mode */
				 ap_smps, /* smps mode AP thinks we're in */
				 driver_smps_mode; /* smps mode request */

	struct work_struct request_smps_work;

	unsigned int flags;

	bool beacon_crc_valid;
	u32 beacon_crc;

	enum {
		IEEE80211_MFP_DISABLED,
		IEEE80211_MFP_OPTIONAL,
		IEEE80211_MFP_REQUIRED
	} mfp; /* management frame protection */

	/*
	 * Bitmask of enabled u-apsd queues,
	 * IEEE80211_WMM_IE_STA_QOSINFO_AC_BE & co. Needs a new association
	 * to take effect.
	 */
	unsigned int uapsd_queues;

	/*
	 * Maximum number of buffered frames AP can deliver during a
	 * service period, IEEE80211_WMM_IE_STA_QOSINFO_SP_ALL or similar.
	 * Needs a new association to take effect.
	 */
	unsigned int uapsd_max_sp_len;

	int wmm_last_param_set;

	u8 use_4addr;

	/* Signal strength from the last Beacon frame in the current BSS. */
	int last_beacon_signal;

	/*
	 * Weighted average of the signal strength from Beacon frames in the
	 * current BSS. This is in units of 1/16 of the signal unit to maintain
	 * accuracy and to speed up calculations, i.e., the value need to be
	 * divided by 16 to get the actual value.
	 */
	int ave_beacon_signal;

	/*
	 * Number of Beacon frames used in ave_beacon_signal. This can be used
	 * to avoid generating less reliable cqm events that would be based
	 * only on couple of received frames.
	 */
	unsigned int count_beacon_signal;

	/*
	 * Last Beacon frame signal strength average (ave_beacon_signal / 16)
	 * that triggered a cqm event. 0 indicates that no event has been
	 * generated for the current association.
	 */
	int last_cqm_event_signal;

	/*
	 * State variables for keeping track of RSSI of the AP currently
	 * connected to and informing driver when RSSI has gone
	 * below/above a certain threshold.
	 */
	int rssi_min_thold, rssi_max_thold;
	int last_ave_beacon_signal;

	struct ieee80211_ht_cap ht_capa; /* configured ht-cap over-rides */
	struct ieee80211_ht_cap ht_capa_mask; /* Valid parts of ht_capa */
};
struct ieee80211_sub_if_data {
	struct list_head list;

	struct wireless_dev wdev;

	/* keys */
	struct list_head key_list;

	/* count for keys needing tailroom space allocation */
	int crypto_tx_tailroom_needed_cnt;

	struct net_device *dev;
	struct ieee80211_local *local;

	unsigned int flags;

	unsigned long state;

	int drop_unencrypted;

	char name[IFNAMSIZ];

	/*
	 * keep track of whether the HT opmode (stored in
	 * vif.bss_info.ht_operation_mode) is valid.
	 */
	bool ht_opmode_valid;

	/* to detect idle changes */
	bool old_idle;

	/* Fragment table for host-based reassembly */
	struct ieee80211_fragment_entry	fragments[4];
	unsigned int fragment_next;

	/* TID bitmap for NoAck policy */
	u16 noack_map;

	struct ieee80211_key __rcu *keys[4 + 2];
	struct ieee80211_key __rcu *default_unicast_key;
	struct ieee80211_key __rcu *default_multicast_key;
	struct ieee80211_key __rcu *default_mgmt_key;

	u16 sequence_number;
	__be16 control_port_protocol;
	bool control_port_no_encrypt;

	struct ieee80211_tx_queue_params tx_conf[IEEE80211_MAX_QUEUES];

	struct work_struct work;
	struct sk_buff_head skb_queue;

	bool arp_filter_state;

	/*
	 * AP this belongs to: self in AP mode and
	 * corresponding AP in VLAN mode, NULL for
	 * all others (might be needed later in IBSS)
	 */
	struct ieee80211_if_ap *bss;

	/* bitmap of allowed (non-MCS) rate indexes for rate control */
	u32 rc_rateidx_mask[IEEE80211_NUM_BANDS];
	u8  rc_rateidx_mcs_mask[IEEE80211_NUM_BANDS][IEEE80211_HT_MCS_MASK_LEN];

	union {
		struct ieee80211_if_ap ap;
		struct ieee80211_if_wds wds;
		struct ieee80211_if_vlan vlan;
		struct ieee80211_if_managed mgd;
		struct ieee80211_if_ibss ibss;
		struct ieee80211_if_mesh mesh;
		u32 mntr_flags;
	} u;

#ifdef CONFIG_MAC80211_DEBUGFS
	struct {
		struct dentry *dir;
		struct dentry *subdir_stations;
		struct dentry *default_unicast_key;
		struct dentry *default_multicast_key;
		struct dentry *default_mgmt_key;
	} debugfs;
#endif
	/* must be last, dynamically sized area in this! */
	struct ieee80211_vif vif;
};
#endif
