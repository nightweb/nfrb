/* 
 * This file is part of the nfrb gem for Ruby.
 * Copyright (C) 2011 Davide Guerri
 *
 * This code is largely derived from nfreader.c of nfdump suite.
 *
 */
	 
#include <ruby.h>

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdarg.h>
#include <errno.h>
#include <time.h>
#include <string.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "nffile.h"
#include "nfx.h"
#include "util.h"

#include "config.h"

#if ( SIZEOF_VOID_P == 8 )
typedef uint64_t    pointer_addr_t;
#else
typedef uint32_t    pointer_addr_t;
#endif

#include "dnc/nffile_inline.c"

VALUE source_address_sym;
VALUE destination_address_sym;
VALUE first_seen_sym;
VALUE last_seen_sym;
VALUE msec_first_seen_sym;
VALUE msec_last_seen_sym;
VALUE protocol_sym;
VALUE source_port_sym;
VALUE destination_port_sym;
VALUE tcp_flags_sym;
VALUE packets_sym;
VALUE bytes_sym;
VALUE forwarding_status_sym;
VALUE tos_sym;
VALUE input_interface_sym;
VALUE output_interface_sym;
VALUE destination_as_sym;
VALUE source_as_sym;
VALUE source_mask_sym;
VALUE destination_mask_sym;
VALUE destination_tos_sym;
VALUE direction_sym;
VALUE next_hop_sym;
VALUE bgp_next_hop_sym;
VALUE source_vlan_sym;
VALUE destination_vlan_sym;

typedef struct nfreader_s {
    extension_map_list_t ext_maps;
} nfreader_t;


static void nfreader_free(void *ptr) {
    nfreader_t *nfreader_prt;
    FreeExtensionMaps(&nfreader_prt->ext_maps);
}

static int process_file(extension_map_list_t *ext_maps, nffile_t *nffile) {
	master_record_t	master_record;
	common_record_t *flow_record = NULL;
	int done, ret, i, j, id;
	char source_ip[40], destination_ip[40], nexthop_ip[40];
	VALUE hash_v;

	hash_v = rb_hash_new();

	done = 0;
	while (!done) {
		// get next data block from file
		ret = ReadBlock(nffile);

		switch (ret) {
			case NF_CORRUPT:
			case NF_ERROR:
				return ret; // Corrupt datafile
			case NF_EOF: {
				done = 1;
				continue;
			} break; // not really needed
		}

		if (nffile->block_header->id == Large_BLOCK_Type) {
			// skip
			continue;
		}

		if (nffile->block_header->id != DATA_BLOCK_TYPE_2) {
			// Can't process block type "nffile->block_header->id". Skip block...
			continue;
		}

		flow_record = nffile->buff_ptr;
		for (i=0; i < nffile->block_header->NumRecords; i++) {
			if (flow_record->type == CommonRecordType) {
				uint32_t map_id = flow_record->ext_map;
				if (ext_maps->slot[map_id] == NULL) {
					// Corrupt data file! No such extension map id: "flow_record->ext_map". Skip record...
				} else {
					ExpandRecord_v2(flow_record, ext_maps->slot[flow_record->ext_map], &master_record);

					// update number of flows matching a given map
					ext_maps->slot[map_id]->ref_count++;

					// Prepare an hash for the ruby block paramater
					if ( (master_record.flags & FLAG_IPV6_ADDR ) != 0 ) { // IPv6
						master_record.v6.srcaddr[0] = htonll(master_record.v6.srcaddr[0]);
						master_record.v6.srcaddr[1] = htonll(master_record.v6.srcaddr[1]);
						master_record.v6.dstaddr[0] = htonll(master_record.v6.dstaddr[0]);
						master_record.v6.dstaddr[1] = htonll(master_record.v6.dstaddr[1]);
						inet_ntop(AF_INET6, master_record.v6.srcaddr, source_ip, sizeof(source_ip));
						inet_ntop(AF_INET6, master_record.v6.dstaddr, destination_ip, sizeof(destination_ip));
					} else {	// IPv4
						master_record.v4.srcaddr = htonl(master_record.v4.srcaddr);
						master_record.v4.dstaddr = htonl(master_record.v4.dstaddr);
						inet_ntop(AF_INET, &master_record.v4.srcaddr, source_ip, sizeof(source_ip));
						inet_ntop(AF_INET, &master_record.v4.dstaddr, destination_ip, sizeof(destination_ip));
					}
					source_ip[40-1] = 0;
					destination_ip[40-1] = 0;

					// netflow common record fields
					rb_hash_aset(hash_v, source_address_sym, rb_tainted_str_new2(source_ip));
					rb_hash_aset(hash_v, destination_address_sym, rb_tainted_str_new2(destination_ip));
					rb_hash_aset(hash_v, first_seen_sym, INT2NUM(master_record.first));
					rb_hash_aset(hash_v, last_seen_sym, INT2NUM(master_record.last));
					rb_hash_aset(hash_v, msec_first_seen_sym, INT2NUM(master_record.msec_first));
					rb_hash_aset(hash_v, msec_last_seen_sym, INT2NUM(master_record.msec_last));
					rb_hash_aset(hash_v, protocol_sym, INT2FIX(master_record.prot));
					rb_hash_aset(hash_v, source_port_sym, INT2FIX(master_record.srcport));
					rb_hash_aset(hash_v, destination_port_sym, INT2FIX(master_record.dstport));
					rb_hash_aset(hash_v, tcp_flags_sym, INT2FIX(master_record.tcp_flags));
					rb_hash_aset(hash_v, packets_sym, INT2NUM((unsigned long long) master_record.dPkts));
					rb_hash_aset(hash_v, bytes_sym, INT2NUM((unsigned long long) master_record.dOctets));
					rb_hash_aset(hash_v, forwarding_status_sym, INT2FIX(master_record.fwd_status));
					rb_hash_aset(hash_v, tos_sym, INT2FIX(master_record.tos));

					// netflow extension fields
					rb_hash_aset(hash_v, input_interface_sym , Qnil);
					rb_hash_aset(hash_v, output_interface_sym, Qnil);
					rb_hash_aset(hash_v, destination_as_sym  , Qnil);
					rb_hash_aset(hash_v, source_as_sym       , Qnil);
					rb_hash_aset(hash_v, source_mask_sym     , Qnil);
					rb_hash_aset(hash_v, destination_mask_sym, Qnil);
					rb_hash_aset(hash_v, destination_tos_sym , Qnil);
					rb_hash_aset(hash_v, direction_sym       , Qnil);
					rb_hash_aset(hash_v, next_hop_sym        , Qnil);
					rb_hash_aset(hash_v, bgp_next_hop_sym    , Qnil);
					rb_hash_aset(hash_v, source_vlan_sym     , Qnil);
					rb_hash_aset(hash_v, destination_vlan_sym, Qnil);

					j=0;
					while ( (id = master_record.map_ref->ex_id[j++]) != 0 ) {
						switch(id) {
							case EX_IO_SNMP_2:
								rb_hash_aset(hash_v, input_interface_sym, INT2FIX(master_record.input));
								rb_hash_aset(hash_v, output_interface_sym, INT2FIX(master_record.output));
								break;
							case EX_IO_SNMP_4:
								rb_hash_aset(hash_v, input_interface_sym, INT2NUM(master_record.input));
								rb_hash_aset(hash_v, output_interface_sym, INT2NUM(master_record.output));
								break;
							case EX_AS_2:
								rb_hash_aset(hash_v, destination_as_sym, INT2FIX(master_record.dstas));
								rb_hash_aset(hash_v, source_as_sym, INT2FIX(master_record.input));
								break;
							case EX_AS_4:
								rb_hash_aset(hash_v, destination_as_sym, INT2NUM(master_record.dstas));
								rb_hash_aset(hash_v, source_as_sym, INT2NUM(master_record.input));
								break;
							case EX_MULIPLE:
								rb_hash_aset(hash_v, source_mask_sym, INT2NUM(master_record.src_mask));
								rb_hash_aset(hash_v, destination_mask_sym, INT2NUM(master_record.dst_mask));
								rb_hash_aset(hash_v, destination_tos_sym, INT2FIX(master_record.dst_tos));
								rb_hash_aset(hash_v, direction_sym, INT2FIX(master_record.dir));
								break;
							case EX_NEXT_HOP_v4:
								master_record.ip_nexthop.v4=htonl(master_record.ip_nexthop.v4);
								nexthop_ip[0] = 0;
								inet_ntop(AF_INET, &master_record.ip_nexthop.v4, nexthop_ip, sizeof(nexthop_ip));
								nexthop_ip[40-1] = 0;
								rb_hash_aset(hash_v, next_hop_sym, rb_tainted_str_new2(nexthop_ip));
								break;
							case EX_NEXT_HOP_v6:
								nexthop_ip[0] = 0;
								master_record.ip_nexthop.v6[0] = htonll(master_record.ip_nexthop.v6[0]);
								master_record.ip_nexthop.v6[1] = htonll(master_record.ip_nexthop.v6[1]);
								inet_ntop(AF_INET6, master_record.ip_nexthop.v6, nexthop_ip, sizeof(nexthop_ip));
								nexthop_ip[40-1] = 0;
								rb_hash_aset(hash_v, next_hop_sym, rb_tainted_str_new2(nexthop_ip));
								break;
							case EX_NEXT_HOP_BGP_v4:
								master_record.ip_nexthop.v4=htonl(master_record.bgp_nexthop.v4);
								nexthop_ip[0] = 0;
								inet_ntop(AF_INET, &master_record.bgp_nexthop.v4, nexthop_ip, sizeof(nexthop_ip));
								nexthop_ip[40-1] = 0;
								rb_hash_aset(hash_v, bgp_next_hop_sym, rb_tainted_str_new2(nexthop_ip));
								break;
							case EX_NEXT_HOP_BGP_v6:
								nexthop_ip[0] = 0;
								master_record.bgp_nexthop.v6[0] = htonll(master_record.bgp_nexthop.v6[0]);
								master_record.bgp_nexthop.v6[1] = htonll(master_record.bgp_nexthop.v6[1]);
								inet_ntop(AF_INET6, master_record.bgp_nexthop.v6, nexthop_ip, sizeof(nexthop_ip));
								nexthop_ip[40-1] = 0;
								rb_hash_aset(hash_v, bgp_next_hop_sym, rb_tainted_str_new2(nexthop_ip));
								break;
							case EX_VLAN:
								rb_hash_aset(hash_v, source_vlan_sym, INT2FIX(master_record.src_vlan));
								rb_hash_aset(hash_v, destination_vlan_sym, INT2FIX(master_record.dst_vlan));
								break;
							default:
							    ;
								// Not implemented
						}
					}

					// Yield to the ruby block
					rb_yield(hash_v);
				}

			} else if (flow_record->type == ExtensionMapType) {
				extension_map_t *map = (extension_map_t *)flow_record;
				Insert_Extension_Map(ext_maps, map);
			} // else Skip unknown record type flow_record->type
			// Advance pointer by number of bytes for netflow record
			flow_record = (common_record_t *)((pointer_addr_t)flow_record + flow_record->size);
		} // for all records
	} // while

    return 0;

} // End of process_data

static VALUE rb_process_file(VALUE self, VALUE filename_v) {
    nfreader_t *nfreader_prt = NULL;
    nffile_t *nffile = NULL;
    int ret;

    Check_Type(filename_v, T_STRING);

    Data_Get_Struct(self, nfreader_t, nfreader_prt);
    InitExtensionMaps(&nfreader_prt->ext_maps);

	nffile = OpenFile(RSTRING_PTR(filename_v), NULL);
	if (!nffile)
	    rb_raise(rb_eIOError, "problem opening file '%s'", RSTRING_PTR(filename_v));

    ret = process_file(&nfreader_prt->ext_maps, nffile);

	CloseFile(nffile);
	DisposeFile(nffile);

	PackExtensionMapList(&nfreader_prt->ext_maps);

    return Qnil;
}

static VALUE rb_process_files(VALUE self, VALUE filenames_a) {
    nfreader_t *nfreader_prt = NULL;
    nffile_t *nffile = NULL;
    VALUE filename_v;
    long i;
    int ret;

    Check_Type(filenames_a, T_ARRAY);

	if (!rb_block_given_p())
		rb_raise(rb_eArgError, "a block is required");

    Data_Get_Struct(self, nfreader_t, nfreader_prt);
    InitExtensionMaps(&nfreader_prt->ext_maps);

    for (i=0 ; i < RARRAY_LEN(filenames_a) ; i++) {
	    filename_v = rb_ary_entry(filenames_a, i);
	    Check_Type(filename_v, T_STRING);

	    nffile = OpenFile(RSTRING_PTR(filename_v), NULL);
	    if (!nffile)
		    rb_raise(rb_eIOError, "problem opening file '%s'", RSTRING_PTR(filename_v));

        ret = process_file(&nfreader_prt->ext_maps, nffile);

	    CloseFile(nffile);
	    DisposeFile(nffile);
    }

	PackExtensionMapList(&nfreader_prt->ext_maps);

    return Qnil;
}


static VALUE rb_nfreader_init(VALUE self) {
    nfreader_t *nfreader_prt = NULL;

    Data_Get_Struct(self, nfreader_t, nfreader_prt);

    return self;
}


VALUE rb_nfreader_new(VALUE nfreader_class) {
    nfreader_t *nfreader_prt = NULL;

    VALUE nfreader_data = Data_Make_Struct(nfreader_class, nfreader_t, NULL, NULL, nfreader_prt);

    rb_obj_call_init(nfreader_data, 0, NULL);

    return nfreader_data;
}


void Init_rb_nfrb() {
	VALUE nfrbModule = rb_define_module("NfRb");

	VALUE rb_nfreader_class = rb_define_class_under(nfrbModule, "NfReader", rb_cObject);
	rb_define_singleton_method(rb_nfreader_class, "new", rb_nfreader_new, 0);
	rb_define_method(rb_nfreader_class, "initialize", rb_nfreader_init, 0);
	rb_define_method(rb_nfreader_class, "process_file", rb_process_file, 1);
	rb_define_method(rb_nfreader_class, "process_files", rb_process_files, 1);

    // Symbols inits
    source_address_sym      = ID2SYM(rb_intern("source_address"));
    destination_address_sym = ID2SYM(rb_intern("destination_address"));
    first_seen_sym          = ID2SYM(rb_intern("first_seen"));
    last_seen_sym           = ID2SYM(rb_intern("last_seen"));
    msec_first_seen_sym     = ID2SYM(rb_intern("msec_first_seen"));
    msec_last_seen_sym      = ID2SYM(rb_intern("msec_last_seen"));
    protocol_sym            = ID2SYM(rb_intern("protocol"));
    source_port_sym         = ID2SYM(rb_intern("source_port"));
    destination_port_sym    = ID2SYM(rb_intern("destination_port"));
    tcp_flags_sym           = ID2SYM(rb_intern("tcp_flags"));
    packets_sym             = ID2SYM(rb_intern("packets"));
    bytes_sym               = ID2SYM(rb_intern("bytes"));
    forwarding_status_sym   = ID2SYM(rb_intern("forwarding_status"));
    tos_sym                 = ID2SYM(rb_intern("tos"));
    input_interface_sym     = ID2SYM(rb_intern("input_interface"));
    output_interface_sym    = ID2SYM(rb_intern("output_interface"));
    destination_as_sym      = ID2SYM(rb_intern("destination_as"));
    source_as_sym           = ID2SYM(rb_intern("source_as"));
    source_mask_sym         = ID2SYM(rb_intern("source_mask"));
    destination_mask_sym    = ID2SYM(rb_intern("destination_mask"));
    destination_tos_sym     = ID2SYM(rb_intern("destination_tos"));
    direction_sym           = ID2SYM(rb_intern("direction"));
    next_hop_sym            = ID2SYM(rb_intern("next_hop"));
    bgp_next_hop_sym        = ID2SYM(rb_intern("bgp_next_hop"));
    source_vlan_sym         = ID2SYM(rb_intern("source_vlan"));
    destination_vlan_sym    = ID2SYM(rb_intern("destination_vlan"));

}