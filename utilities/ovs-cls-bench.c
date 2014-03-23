/* Copyright (c) 2014 Nicira, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License. */

#include <config.h>

#include <sys/time.h>
#include <sys/resource.h>

#include "match.h"
#include "classifier.h"
#include "ofp-util.h"
#include "ofp-parse.h"
#include "timeval.h"
#include "vlog.h"

VLOG_DEFINE_THIS_MODULE(cls_bench);

static void usage(void);
static void benchmark(struct classifier *);

int
main(int argc, char *argv[])
{
    enum ofputil_protocol usable_protocols;
    struct ofputil_flow_mod *fms = NULL;
    static struct classifier cls;
    struct cls_rule *rules;
    size_t n_fms, i;
    char *error;

    set_program_name(argv[0]);
    vlog_set_levels(NULL, VLF_ANY_FACILITY, VLL_DBG);


    if (argc < 2) {
        usage();
    }

    if (!strncmp(argv[1], "hsa", 3)) {
        VLOG_DBG("Enabling HSA");
        cls.enable_hsa = true;
    }

    VLOG_DBG("using file: %s", argv[2]);
    error = parse_ofp_flow_mod_file(argv[2], OFPFC_ADD, &fms, &n_fms,
                                    &usable_protocols);
    if (error) {
        ovs_fatal(0, "%s", error);
    }

    classifier_init(&cls, flow_segment_u32s);

    fat_rwlock_wrlock(&cls.rwlock);
    rules = xmalloc(n_fms * sizeof *rules);
    for (i = 0; i < n_fms; i++) {
        struct cls_rule *rule = &rules[i];
        struct cls_rule *displaced_rule;

        cls_rule_init(rule, &fms[i].match, fms[i].priority);
        displaced_rule = classifier_replace(&cls, rule);
        if (displaced_rule) {
            cls_rule_destroy(displaced_rule);
            VLOG_WARN("TODO");
        }
    }
    fat_rwlock_unlock(&cls.rwlock);

    benchmark(&cls);

    free(rules);
    free(fms);
    return 0;
}

static void
usage(void) {
    printf("%s [hsa | decision_tree | standard] <flow_file>\n", program_name);
    exit(EXIT_SUCCESS);
}

static void
benchmark(struct classifier *cls)
{
    struct timespec before, after;
    struct rusage rbefore, rafter;
    struct flow_wildcards wc;
    struct match match_wc_str;
    struct flow flow;
    size_t i;

    memset(&flow, 0, sizeof flow);
    flow.in_port.ofp_port = OFPP_LOCAL;
    flow.dl_type = htons(ETH_TYPE_IP);
    flow.nw_proto = IPPROTO_TCP;

    fat_rwlock_rdlock(&cls->rwlock);
    clock_gettime(CLOCK_MONOTONIC_RAW, &before);
    getrusage(RUSAGE_SELF, &rbefore);
    //for (i = 0; i < 10000000; i++) {
    for (i = 0; i < 5; i++) {
        eth_addr_random(flow.dl_src);
        eth_addr_random(flow.dl_dst);
        flow.nw_src = htonl(random_uint32());
        flow.nw_dst = htonl(random_uint32());
        flow.tp_src = htons(random_uint16());
        //flow.tp_dst = htons(random_uint16());
        flow.tp_dst = htons(998+i);
        flow_wildcards_init_catchall(&wc);
        //VLOG_DBG("Finding relevant wc's for flow=%s\n",
        //         flow_to_string(flow));
        VLOG_DBG("Finding relevant wc's for flow: tp_dst=%d (0x%04x)",
                 ntohs(flow.tp_dst), ntohs(flow.tp_dst));
        classifier_lookup(cls, &flow, &wc);
        match_init(&match_wc_str, &flow, &wc);
        VLOG_DBG("Relevant fields: %s", match_to_string(&match_wc_str, 0));
    }
    getrusage(RUSAGE_SELF, &rafter);
    clock_gettime(CLOCK_MONOTONIC_RAW, &after);
    fat_rwlock_unlock(&cls->rwlock);

    printf("real        %lldms\n"
           "user        %lldms\n"
           "sys         %lldms\n"
           "soft faults %ld\n"
           "hard faults %ld\n",
           timespec_to_msec(&after) - timespec_to_msec(&before),
           timeval_to_msec(&rafter.ru_utime)
               - timeval_to_msec(&rbefore.ru_utime),
           timeval_to_msec(&rafter.ru_stime)
               - timeval_to_msec(&rbefore.ru_stime),
            rafter.ru_minflt - rbefore.ru_minflt,
            rafter.ru_majflt - rbefore.ru_majflt);
}
