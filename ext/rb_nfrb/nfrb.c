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

static VALUE process_file(VALUE self, VALUE filename_v) {
	master_record_t	master_record;
	common_record_t *flow_record = NULL;
	int done, ret, i;
	nffile_t *nffile = NULL;
	extension_map_list_t extension_map_list;
	VALUE hash_v = Qnil;
	char source_ip[40], destination_ip[40];
	static char *filename = NULL;
	
	if (!rb_block_given_p())
		rb_raise(rb_eArgError, "a block is required");		
				
	Check_Type(filename_v, T_STRING);
	filename = RSTRING(filename_v)->ptr;

	InitExtensionMaps(&extension_map_list);

	nffile = OpenFile(filename, NULL);
	if (!nffile)
		rb_raise(rb_eIOError, "problem opening file '%s'", filename);

	hash_v = rb_hash_new();

	done = 0;
	while (!done) {
		// get next data block from file
		ret = ReadBlock(nffile);

		switch (ret) {
			case NF_CORRUPT:
			case NF_ERROR:
				if (ret == NF_CORRUPT) 
					rb_raise(rb_eIOError, "corrupt data file '%s'", filename);
				else 
					rb_raise(rb_eIOError, "read error in file '%s': %s", filename, strerror(errno));
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
				if (extension_map_list.slot[map_id] == NULL) {
					// Corrupt data file! No such extension map id: "flow_record->ext_map". Skip record...
				} else {
					ExpandRecord_v2(flow_record, extension_map_list.slot[flow_record->ext_map], &master_record);

					// update number of flows matching a given map
					extension_map_list.slot[map_id]->ref_count++;
			
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
	
					rb_hash_aset(hash_v, ID2SYM(rb_intern("source_address")), rb_tainted_str_new2(source_ip));
					rb_hash_aset(hash_v, ID2SYM(rb_intern("destination_address")), rb_tainted_str_new2(destination_ip));
					rb_hash_aset(hash_v, ID2SYM(rb_intern("first_seen")), INT2NUM(master_record.first));	
					rb_hash_aset(hash_v, ID2SYM(rb_intern("last_seen")), INT2NUM(master_record.last));
					rb_hash_aset(hash_v, ID2SYM(rb_intern("msec_first_seen")), INT2NUM(master_record.msec_first));	
					rb_hash_aset(hash_v, ID2SYM(rb_intern("msec_last_seen")), INT2NUM(master_record.msec_last));
					rb_hash_aset(hash_v, ID2SYM(rb_intern("protocol")), INT2FIX(master_record.prot));
					rb_hash_aset(hash_v, ID2SYM(rb_intern("source_port")), INT2FIX(master_record.srcport));
					rb_hash_aset(hash_v, ID2SYM(rb_intern("destination_port")), INT2FIX(master_record.dstport));	
					rb_hash_aset(hash_v, ID2SYM(rb_intern("packets")), INT2NUM((unsigned long long) master_record.dPkts));
					rb_hash_aset(hash_v, ID2SYM(rb_intern("bytes")), INT2NUM((unsigned long long) master_record.dOctets));	
					rb_hash_aset(hash_v, ID2SYM(rb_intern("source_as")), INT2NUM(master_record.srcas));
					rb_hash_aset(hash_v, ID2SYM(rb_intern("destination_as")), INT2NUM(master_record.dstas));	
					
					// Yield to the ruby block
					rb_yield(hash_v);
				}

			} else if (flow_record->type == ExtensionMapType) {
				extension_map_t *map = (extension_map_t *)flow_record;
				Insert_Extension_Map(&extension_map_list, map);
			} // else Skip unknown record type flow_record->type
			// Advance pointer by number of bytes for netflow record
			flow_record = (common_record_t *)((pointer_addr_t)flow_record + flow_record->size);	
		} // for all records
	} // while

	CloseFile(nffile);
	DisposeFile(nffile);

	PackExtensionMapList(&extension_map_list);
	FreeExtensionMaps(&extension_map_list);
	
	return Qnil;
} // End of process_data

void Init_rb_nfrb() {
	VALUE nfrbModule = rb_define_module("NfRb");

	VALUE nffileClass = rb_define_class_under(nfrbModule, "NfFile", rb_cObject);
	rb_define_method(nffileClass, "process_file", process_file, 1);
}