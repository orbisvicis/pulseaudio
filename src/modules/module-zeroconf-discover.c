/***
  This file is part of PulseAudio.

  Copyright 2004-2006 Lennart Poettering

  PulseAudio is free software; you can redistribute it and/or modify
  it under the terms of the GNU Lesser General Public License as
  published by the Free Software Foundation; either version 2.1 of the
  License, or (at your option) any later version.

  PulseAudio is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  General Public License for more details.

  You should have received a copy of the GNU Lesser General Public
  License along with PulseAudio; if not, see <http://www.gnu.org/licenses/>.
***/

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <avahi-client/client.h>
#include <avahi-client/lookup.h>
#include <avahi-common/alternative.h>
#include <avahi-common/error.h>
#include <avahi-common/domain.h>
#include <avahi-common/malloc.h>

#include <pulse/xmalloc.h>

#include <pulsecore/core-util.h>
#include <pulsecore/log.h>
#include <pulsecore/hashmap.h>
#include <pulsecore/modargs.h>
#include <pulsecore/namereg.h>
#include <pulsecore/avahi-wrap.h>

PA_MODULE_AUTHOR("Lennart Poettering");
PA_MODULE_DESCRIPTION("mDNS/DNS-SD Service Discovery");
PA_MODULE_VERSION(PACKAGE_VERSION);
PA_MODULE_LOAD_ONCE(true);

#define SERVICE_TYPE_SINK "_pulse-sink._tcp"
#define SERVICE_TYPE_SOURCE "_non-monitor._sub._pulse-source._tcp"

static const char* const valid_modargs[] = {
    "disable_ipv4",
    "disable_ipv6",
    "one_per_name_type",
    NULL
};

struct userdata {
    pa_core *core;
    pa_module *module;

    pa_hook_slot *module_unlink_slot;

    AvahiPoll *avahi_poll;
    AvahiClient *client;
    AvahiServiceBrowser *source_browser, *sink_browser;
    AvahiProtocol protocol;

    pa_hashmap *tunnels_loaded;
    pa_hashmap *tunnels_loaded_by_index;
    pa_hashmap *tunnels_queued;
};

typedef struct {
    pa_object parent;

    struct userdata *userdata;

    AvahiIfIndex interface;
    AvahiProtocol protocol;
    char *name, *type, *domain;

    uint32_t module_index;
} tunnel;

PA_DEFINE_PRIVATE_CLASS(tunnel, pa_object);

static int module_index_compare(const void *a, const void *b) {
    uint32_t idx_a = *(uint32_t *)a;
    uint32_t idx_b = *(uint32_t *)b;
    return idx_a < idx_b ? -1 : (idx_a > idx_b ? 1 : 0);
}

static unsigned module_index_hash(const void *p) {
    uint32_t idx_p = *(uint32_t *)p;
    return (unsigned) idx_p;
}

static unsigned tunnel_hash_simple(const void *p) {
    const tunnel *t = p;

    return
        pa_idxset_string_hash_func(t->name) +
        pa_idxset_string_hash_func(t->type);
}

static unsigned tunnel_hash(const void *p) {
    const tunnel *t = p;

    return
        (unsigned) t->interface +
        (unsigned) t->protocol +
        pa_idxset_string_hash_func(t->name) +
        pa_idxset_string_hash_func(t->type) +
        pa_idxset_string_hash_func(t->domain);
}

static int tunnel_compare_simple(const void *a, const void *b) {
    const tunnel *ta = a, *tb = b;
    int r;

    if ((r = strcmp(ta->name, tb->name)))
        return r;
    if ((r = strcmp(ta->type, tb->type)))
        return r;

    return 0;
}

static int tunnel_compare(const void *a, const void *b) {
    const tunnel *ta = a, *tb = b;
    int r;

    if (ta->interface != tb->interface)
        return 1;
    if (ta->protocol != tb->protocol)
        return 1;
    if ((r = strcmp(ta->name, tb->name)))
        return r;
    if ((r = strcmp(ta->type, tb->type)))
        return r;
    if ((r = strcmp(ta->domain, tb->domain)))
        return r;

    return 0;
}

static void tunnel_free(tunnel *t) {
    pa_assert(t);
    pa_xfree(t->name);
    pa_xfree(t->type);
    pa_xfree(t->domain);
    pa_xfree(t);
}

static void tunnel_ref_free(pa_object *o) {
    tunnel *t = tunnel_cast(o);

    pa_assert(t);
    pa_assert(!tunnel_refcnt(t));

    tunnel_free(t);
}

static tunnel *tunnel_new(
        struct userdata *u,
        AvahiIfIndex interface, AvahiProtocol protocol,
        const char *name, const char *type, const char *domain) {

    tunnel *t = pa_object_new(tunnel);
    t->parent.free = tunnel_ref_free;
    t->userdata = u;
    t->interface = interface;
    t->protocol = protocol;
    t->name = pa_xstrdup(name);
    t->type = pa_xstrdup(type);
    t->domain = pa_xstrdup(domain);
    t->module_index = PA_IDXSET_INVALID;
    return t;
}

static bool tunnel_loaded(tunnel *t) {
    return t->module_index != PA_IDXSET_INVALID;
}

static void resolver_cb(
        AvahiServiceResolver *r,
        AvahiIfIndex interface, AvahiProtocol protocol,
        AvahiResolverEvent event,
        const char *name, const char *type, const char *domain,
        const char *host_name, const AvahiAddress *a, uint16_t port,
        AvahiStringList *txt,
        AvahiLookupResultFlags flags,
        void *userdata) {

    bool remove = false;
    tunnel *tnl = userdata;
    struct userdata *u;

    pa_assert(tnl);

    u = tnl->userdata;

    pa_assert(u);

    pa_assert(tnl->interface == interface && tnl->protocol == protocol &&
              !strcmp(tnl->name, name) && !strcmp(tnl->type, type) && !strcmp(tnl->domain, domain));

    /* Doesn't exist; exists but different; exists but already loaded */
    if (pa_hashmap_get(u->tunnels_loaded, tnl) != tnl || tunnel_loaded(tnl))
        goto finish;

    if (u->protocol != AVAHI_PROTO_UNSPEC && u->protocol != protocol) {
        pa_log_warn("Expected address protocol '%i' but received '%i'", u->protocol, protocol);
        remove = true;
        goto finish;
    }

    if (event != AVAHI_RESOLVER_FOUND) {
        pa_log("Resolving of '%s' failed: %s", name, avahi_strerror(avahi_client_errno(u->client)));
        remove = true;
        goto finish;
    }
    else {
        char *device = NULL, *dname, *module_name, *args;
        const char *t;
        char *if_suffix = NULL;
        char at[AVAHI_ADDRESS_STR_MAX], cmt[PA_CHANNEL_MAP_SNPRINT_MAX];
        char *properties = NULL;
        pa_sample_spec ss;
        pa_channel_map cm;
        AvahiStringList *l;
        bool channel_map_set = false;
        pa_module *m;

        ss = u->core->default_sample_spec;
        cm = u->core->default_channel_map;

        for (l = txt; l; l = l->next) {
            char *key, *value;
            pa_assert_se(avahi_string_list_get_pair(l, &key, &value, NULL) == 0);

            if (pa_streq(key, "device")) {
                pa_xfree(device);
                device = value;
                value = NULL;
            } else if (pa_streq(key, "rate"))
                ss.rate = (uint32_t) atoi(value);
            else if (pa_streq(key, "channels"))
                ss.channels = (uint8_t) atoi(value);
            else if (pa_streq(key, "format"))
                ss.format = pa_parse_sample_format(value);
            else if (pa_streq(key, "icon-name")) {
                pa_xfree(properties);
                properties = pa_sprintf_malloc("device.icon_name=%s", value);
            } else if (pa_streq(key, "channel_map")) {
                pa_channel_map_parse(&cm, value);
                channel_map_set = true;
            }

            avahi_free(key);
            avahi_free(value);
        }

        if (!channel_map_set && cm.channels != ss.channels)
            pa_channel_map_init_extend(&cm, ss.channels, PA_CHANNEL_MAP_DEFAULT);

        if (!pa_sample_spec_valid(&ss)) {
            pa_log("Service '%s' contains an invalid sample specification.", name);
            avahi_free(device);
            pa_xfree(properties);
            remove = true;
            goto finish;
        }

        if (!pa_channel_map_valid(&cm) || cm.channels != ss.channels) {
            pa_log("Service '%s' contains an invalid channel map.", name);
            avahi_free(device);
            pa_xfree(properties);
            remove = true;
            goto finish;
        }

        if (device)
            dname = pa_sprintf_malloc("tunnel.%s.%s", host_name, device);
        else
            dname = pa_sprintf_malloc("tunnel.%s", host_name);

        if (!pa_namereg_is_valid_name(dname)) {
            pa_log("Cannot construct valid device name from credentials of service '%s'.", dname);
            avahi_free(device);
            pa_xfree(dname);
            pa_xfree(properties);
            remove = true;
            goto finish;
        }

        t = strstr(type, "sink") ? "sink" : "source";
        if (a->proto == AVAHI_PROTO_INET6 &&
            a->data.ipv6.address[0] == 0xfe &&
            (a->data.ipv6.address[1] & 0xc0) == 0x80)
            if_suffix = pa_sprintf_malloc("%%%d", interface);

        module_name = pa_sprintf_malloc("module-tunnel-%s", t);
        args = pa_sprintf_malloc("server=[%s%s]:%u "
                                 "%s=%s "
                                 "format=%s "
                                 "channels=%u "
                                 "rate=%u "
                                 "%s_properties=%s "
                                 "%s_name=%s "
                                 "channel_map=%s",
                                 avahi_address_snprint(at, sizeof(at), a),
                                 if_suffix ? if_suffix : "", port,
                                 t, device,
                                 pa_sample_format_to_string(ss.format),
                                 ss.channels,
                                 ss.rate,
                                 t, properties ? properties : "",
                                 t, dname,
                                 pa_channel_map_snprint(cmt, sizeof(cmt), &cm));

        pa_log_debug("Loading %s with arguments '%s'", module_name, args);

        if (pa_module_load(&m, u->core, module_name, args) >= 0) {
            tnl->module_index = m->index;
            pa_hashmap_put(u->tunnels_loaded_by_index, &tnl->module_index, tnl);
        }
        else
            remove = true;

        pa_xfree(module_name);
        pa_xfree(dname);
        pa_xfree(args);
        pa_xfree(if_suffix);
        pa_xfree(properties);
        avahi_free(device);
    }

finish:

    if (remove) {
        pa_hashmap_remove(u->tunnels_loaded, tnl);
        tunnel_unref(tnl);
    }

    avahi_service_resolver_free(r);
    tunnel_unref(tnl);
    return;
}

static void tunnel_add_from_queue_cb(pa_mainloop_api *a, pa_defer_event *e, void *userdata) {
    tunnel *t_search = userdata;
    tunnel *t_queued;
    struct userdata *u;
    void *state;

    pa_assert(t_search);

    u = t_search->userdata;

    pa_assert(u);

    if (pa_hashmap_get(u->tunnels_loaded, t_search))
        goto finish;

    PA_HASHMAP_FOREACH(t_queued, u->tunnels_queued, state) {
        if (!tunnel_compare_simple(t_queued, t_search)) {
            if (!avahi_service_resolver_new(u->client, t_queued->interface, t_queued->protocol,
                                            t_queued->name, t_queued->type, t_queued->domain, u->protocol,
                                            0, resolver_cb, t_queued)) {
                pa_log("avahi_service_resolver_new() failed: %s", avahi_strerror(avahi_client_errno(u->client)));
                continue;
            }
            tunnel_ref(t_queued);
            pa_hashmap_remove(u->tunnels_queued, t_queued);
            pa_hashmap_put(u->tunnels_loaded, t_queued, t_queued);
            break;
        }
    }

finish:

    tunnel_unref(t_search);
    a->defer_free(e);
}

static pa_hook_result_t tunnel_remove_cb(void *hook_data, void *call_data, void *slot_data) {
    struct userdata *u = slot_data;
    pa_module *m = call_data;

    tunnel *t;

    pa_assert(u);
    pa_assert(m);

    if (!(t = pa_hashmap_remove(u->tunnels_loaded_by_index, &m->index)))
        return PA_HOOK_OK;

    pa_assert(pa_hashmap_remove(u->tunnels_loaded, t) == t);

    if (u->tunnels_queued)
        u->core->mainloop->defer_new(u->core->mainloop, tunnel_add_from_queue_cb, t);
    else
        tunnel_unref(t);

    return PA_HOOK_OK;
}

static void browser_cb(
        AvahiServiceBrowser *b,
        AvahiIfIndex interface, AvahiProtocol protocol,
        AvahiBrowserEvent event,
        const char *name, const char *type, const char *domain,
        AvahiLookupResultFlags flags,
        void *userdata) {

    struct userdata *u = userdata;
    tunnel *t_new;
    tunnel *t_old_loaded;
    tunnel *t_old_queued;

    pa_assert(u);

    if (flags & AVAHI_LOOKUP_RESULT_LOCAL)
        return;

    if (event != AVAHI_BROWSER_NEW && event != AVAHI_BROWSER_REMOVE)
        return;

    if (u->protocol != AVAHI_PROTO_UNSPEC && u->protocol != protocol) {
        pa_log_warn("Expected query protocol '%i' but received '%i'", u->protocol, protocol);
        return;
    }

    t_new = tunnel_new(u, interface, protocol, name, type, domain);

    if (event == AVAHI_BROWSER_NEW) {

        if (!(t_old_loaded = pa_hashmap_get(u->tunnels_loaded, t_new))) {
            /* We ignore the returned resolver object here, since the we don't
             * need to attach any special data to it, and we can still destroy
             * it from the callback */
            if (!avahi_service_resolver_new(u->client, interface, protocol, name, type, domain, u->protocol, 0, resolver_cb, t_new)) {
                pa_log("avahi_service_resolver_new() failed: %s", avahi_strerror(avahi_client_errno(u->client)));
                tunnel_unref(t_new);
                return;
            }
            if (u->tunnels_queued && (t_old_queued = pa_hashmap_remove(u->tunnels_queued, t_new))) {
                tunnel_unref(t_old_queued);
            }
            pa_hashmap_put(u->tunnels_loaded, t_new, t_new);
            tunnel_ref(t_new);
            return;
        }
        else if (u->tunnels_queued && tunnel_compare(t_new, t_old_loaded) && !pa_hashmap_get(u->tunnels_queued, t_new)) {
            pa_hashmap_put(u->tunnels_queued, t_new, t_new);
            return;
        }
        tunnel_unref(t_new);
        return;

    } else if (event == AVAHI_BROWSER_REMOVE) {

        if (u->tunnels_queued) {
            if ((t_old_queued = pa_hashmap_remove(u->tunnels_queued, t_new))) {
                tunnel_unref(t_old_queued);
            }
            if ((t_old_loaded = pa_hashmap_get(u->tunnels_loaded, t_new)) && !tunnel_compare(t_new, t_old_loaded)) {
                pa_hashmap_remove(u->tunnels_loaded, t_old_loaded);
                pa_hashmap_remove(u->tunnels_loaded_by_index, &t_old_loaded->module_index);
                pa_module_unload_request_by_index(u->core, t_old_loaded->module_index, true);
                /* Allow queued AVAHI_BROWSER_REMOVE events to be processed
                 * first. The event object is ignored as it can be destroyed
                 * from the callback. */
                u->core->mainloop->defer_new(u->core->mainloop, tunnel_add_from_queue_cb, t_old_loaded);
            }
        }
        else if ((t_old_loaded = pa_hashmap_remove(u->tunnels_loaded, t_new))) {
            pa_hashmap_remove(u->tunnels_loaded, t_old_loaded);
            pa_hashmap_remove(u->tunnels_loaded_by_index, &t_old_loaded->module_index);
            pa_module_unload_request_by_index(u->core, t_old_loaded->module_index, true);
            tunnel_unref(t_old_loaded);
        }
        tunnel_unref(t_new);
        return;

    } else

        tunnel_unref(t_new);
}

/* Avahi browser and resolver callbacks only receive a concrete protocol;
 * always AVAHI_PROTO_INET or AVAHI_PROTO_INET6 and never AVAHI_PROTO_UNSPEC. A
 * new browser given UNSPEC will receive both (separate) INET and INET6 events.
 * A new resolver given a query protocol of UNSPEC will default to querying
 * with INET6. A new resolver given an address protocol of UNSPEC will always
 * resolve a service to an address matching the query protocol. So a resolver
 * with UNSPEC/UNSPEC is equivalent to INET6/INET6. By default the avahi daemon
 * publishes AAAA (IPv6) records over IPv4, but not A (IPv4) records over IPv6
 * (see 'publish-aaaa-on-ipv4' and 'publish-a-on-ipv6' in 'avahi-daemon.conf').
 * That's why, given most daemons, all four combinations of concrete query and
 * address protocols resolve except INET addresses via INET6 queries. */

static void client_callback(AvahiClient *c, AvahiClientState state, void *userdata) {
    struct userdata *u = userdata;

    pa_assert(c);
    pa_assert(u);

    u->client = c;

    switch (state) {
        case AVAHI_CLIENT_S_REGISTERING:
        case AVAHI_CLIENT_S_RUNNING:
        case AVAHI_CLIENT_S_COLLISION:

            if (!u->sink_browser) {

                if (!(u->sink_browser = avahi_service_browser_new(
                              c,
                              AVAHI_IF_UNSPEC,
                              u->protocol,
                              SERVICE_TYPE_SINK,
                              NULL,
                              0,
                              browser_cb, u))) {

                    pa_log("avahi_service_browser_new() failed: %s", avahi_strerror(avahi_client_errno(c)));
                    pa_module_unload_request(u->module, true);
                }
            }

            if (!u->source_browser) {

                if (!(u->source_browser = avahi_service_browser_new(
                              c,
                              AVAHI_IF_UNSPEC,
                              u->protocol,
                              SERVICE_TYPE_SOURCE,
                              NULL,
                              0,
                              browser_cb, u))) {

                    pa_log("avahi_service_browser_new() failed: %s", avahi_strerror(avahi_client_errno(c)));
                    pa_module_unload_request(u->module, true);
                }
            }

            break;

        case AVAHI_CLIENT_FAILURE:
            if (avahi_client_errno(c) == AVAHI_ERR_DISCONNECTED) {
                int error;

                pa_log_debug("Avahi daemon disconnected.");

                /* Frees all associated resources, i.e. browsers, resolvers,
                 * and groups. */
                avahi_client_free(c);
                u->client = NULL;
                u->sink_browser = u->source_browser = NULL;

                if (!avahi_client_new(u->avahi_poll, AVAHI_CLIENT_NO_FAIL, client_callback, u, &error)) {
                    pa_log("avahi_client_new() failed: %s", avahi_strerror(error));
                    pa_module_unload_request(u->module, true);
                }

                break;
            }

            /* Fall through */

        case AVAHI_CLIENT_CONNECTING:

            if (u->sink_browser) {
                avahi_service_browser_free(u->sink_browser);
                u->sink_browser = NULL;
            }

            if (u->source_browser) {
                avahi_service_browser_free(u->source_browser);
                u->source_browser = NULL;
            }

            break;

        default: ;
    }
}

int pa__init(pa_module*m) {

    struct userdata *u;
    pa_modargs *ma = NULL;
    bool disable_ipv4 = false;
    bool disable_ipv6 = false;
    bool one_per_name_type = false;
    AvahiProtocol protocol;
    int error;

    if (!(ma = pa_modargs_new(m->argument, valid_modargs))) {
        pa_log("Failed to parse module arguments.");
        goto fail;
    }

    if (pa_modargs_get_value_boolean(ma, "disable_ipv4", &disable_ipv4) < 0) {
        pa_log("Failed to parse argument 'disable_ipv4'.");
        goto fail;
    }

    if (pa_modargs_get_value_boolean(ma, "disable_ipv6", &disable_ipv6) < 0) {
        pa_log("Failed to parse argument 'disable_ipv6'.");
        goto fail;
    }

    if (pa_modargs_get_value_boolean(ma, "one_per_name_type", &one_per_name_type) < 0) {
        pa_log("Failed to parse argument 'one_per_name_type'.");
        goto fail;
    }

    if (disable_ipv4 && disable_ipv6) {
        pa_log("Given both 'disable_ipv4' and 'disable_ipv6', unloading.");
        goto fail;
    } else if (disable_ipv4)
        protocol = AVAHI_PROTO_INET6;
    else if (disable_ipv6)
        protocol = AVAHI_PROTO_INET;
    else
        protocol = AVAHI_PROTO_UNSPEC;


    m->userdata = u = pa_xnew(struct userdata, 1);
    u->core = m->core;
    u->module = m;
    u->client = NULL;
    u->sink_browser = u->source_browser = NULL;
    u->protocol = protocol;

    if (one_per_name_type) {
        u->tunnels_loaded = pa_hashmap_new(tunnel_hash_simple, tunnel_compare_simple);
        u->tunnels_queued = pa_hashmap_new(tunnel_hash, tunnel_compare);
    }
    else {
        u->tunnels_loaded = pa_hashmap_new(tunnel_hash, tunnel_compare);
        u->tunnels_queued = NULL;
    }
    u->tunnels_loaded_by_index = pa_hashmap_new(module_index_hash, module_index_compare);


    u->avahi_poll = pa_avahi_poll_new(m->core->mainloop);

    /* The client callback is run for the first time within 'avahi_client_new',
     * and on AVAHI_CLIENT_FAILURE may free the old client and create a new
     * client assigned to 'userdata.client'. If so 'avahi_client_new' will
     * return a pointer to already-freed data. When 'avahi_client_new' fails it
     * returns NULL and does not run the callback; 'userdata.client' remains
     * NULL (see above). Otherwise the callback is run, ensuring that
     * 'userdata.client' is appropriately set. */
    if (!avahi_client_new(u->avahi_poll, AVAHI_CLIENT_NO_FAIL, client_callback, u, &error)) {
        pa_log("pa_avahi_client_new() failed: %s", avahi_strerror(error));
        goto fail;
    }

    u->module_unlink_slot = pa_hook_connect(&u->core->hooks[PA_CORE_HOOK_MODULE_UNLINK], PA_HOOK_NORMAL, tunnel_remove_cb, u);

    pa_modargs_free(ma);

    return 0;

fail:
    pa__done(m);

    if (ma)
        pa_modargs_free(ma);

    return -1;
}

void pa__done(pa_module*m) {
    struct userdata *u;
    tunnel *t;
    pa_assert(m);

    if (!(u = m->userdata))
        return;

    if (u->client)
        avahi_client_free(u->client);

    if (u->avahi_poll)
        pa_avahi_poll_free(u->avahi_poll);

    if (u->tunnels_queued) {
        while ((t = pa_hashmap_steal_first(u->tunnels_queued)))
            tunnel_free(t);

        pa_hashmap_free(u->tunnels_queued);
    }

    if (u->tunnels_loaded) {
        while ((t = pa_hashmap_steal_first(u->tunnels_loaded))) {
            if (u->tunnels_loaded_by_index)
                pa_assert(pa_hashmap_remove(u->tunnels_loaded_by_index, &t->module_index) == t);
            pa_module_unload_request_by_index(u->core, t->module_index, true);
            tunnel_free(t);
        }

        if (u->tunnels_loaded_by_index)
            pa_assert(pa_hashmap_isempty(u->tunnels_loaded_by_index));

        pa_hashmap_free(u->tunnels_loaded);
    }

    if (u->tunnels_loaded_by_index)
        pa_hashmap_free(u->tunnels_loaded_by_index);

    if (u->module_unlink_slot)
        pa_hook_slot_free(u->module_unlink_slot);

    pa_xfree(u);
}
