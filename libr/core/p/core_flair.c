/* radare - LGPL - Copyright 2014 - pancake */
#if 0
gcc -o core_test.so -fPIC `pkg-config --cflags --libs r_core` core_test.c -shared
mkdir -p ~/.config/radare2/plugins
mv core_test.so ~/.config/radare2/plugins
#endif

#include <r_types.h>
#include <r_lib.h>
#include <r_cmd.h>
#include <r_core.h>
#include <r_cons.h>
#include <string.h>
#include <r_anal.h>
#include <zlib.h>

#undef R_API
#define R_API static
#undef R_IPI
#define R_IPI static

typedef struct idasig_t {
	char magic[6];
	ut8  version;
	ut8  arch;
	ut32 file_bs;
	ut16 os_bs;
	ut16 apptype_bs;
	ut16 flags;
	ut16 modules;
	ut16 crc;
	char ctype[12];
	ut8  name_len;
	ut16 crc_;
} __attribute__((packed)) idasig_t;

typedef struct bb {
	ut8 *buf;
	ut32 pos, size;
} bb;

static bb *init_bb (ut8 *ptr, ut32 size) {
	bb *b = R_NEW0(bb);
	if (!b)
		return NULL;
	b->buf = ptr;
	b->pos = 0;
	b->size = size;
	return b;
}

static ut32 read_byte (bb *b) {
	return b->buf[b->pos++];
}

static ut16 read_short (bb *b) {
	ut16 r = 
		b->buf[b->pos+0] << 8 | 
		b->buf[b->pos+1];
	b->pos += 2;
	return r;
}

static ut32 read_word (bb *b) {
	ut32 r = 
		b->buf[b->pos+3] << 24 | 
		b->buf[b->pos+2] << 16 | 
		b->buf[b->pos+1] << 8  | 
		b->buf[b->pos+0];
	b->pos += 4;
	return r;
}

static ut32 read_shift (bb *b) {
	ut8 r = b->buf[b->pos++];
	if (r&0x80)
		return (r&0x7f) << 8 | b->buf[b->pos++];
	return r;
}

static ut32 r_sig_explode_mask (bb *b) {
	ut32 r = read_byte(b);

	if ((r&0x80) != 0x80)
		return r;

	if ((r&0xc0) != 0xc0)
		return (r&0x7f) << 8 | read_byte(b);

	if ((r&0xe0) != 0xe0)
		return (r&0x3f) << 24 | read_byte(b) << 16 | read_short(b);

	return read_short(b) << 16 | read_short(b);
}

#define R_SIG_NAME_MAX 1024 

typedef struct RSigName {
	ut32 offset;
	char name[R_SIG_NAME_MAX];
} RSigName;

typedef struct RSigSubLeaf {
	ut8  flags;
	ut16 check_off;
	ut8  check_val;
	RList *names_list;
} RSigSubLeaf;

typedef struct RSigLeaf {
	RList *sub_list;
	ut32 crc_len;
	ut32 crc_val;
} RSigLeaf;

typedef struct RSigNode {
	RList *child_list;
	RList *leaf_list;
	ut32 length;
	ut8 *match;
	ut32 mask;
	ut8 *maskp;
} RSigNode;

#define POLY 0x8408
unsigned short crc16(unsigned char *data_p, size_t length)
{
	unsigned char i;
	unsigned int data;

	if ( length == 0 ) 
		return 0;
	unsigned int crc = 0xFFFF;
	do
	{
		data = *data_p++;
		for ( i=0; i < 8; i++ )
		{
			if ( (crc ^ data) & 1 )
				crc = (crc >> 1) ^ POLY;
			else
				crc >>= 1;
			data >>= 1;
		}
	} while ( --length != 0 );

	crc = ~crc;
	data = crc;
	crc = (crc << 8) | ((data >> 8) & 0xff);
	return (unsigned short)(crc);
}

static int r_sig_node_match (void *buf, unsigned long buf_size, RSigNode *node) {
	int i;
	if (node->length > buf_size)
		return -1;
	for (i = 0; i < node->length; i++) {
		if ((node->match[i]&node->maskp[i]) != (((ut8*)buf)[i]&node->maskp[i]))
			return -1;
	}

	return 0;
}

static void r_sig_node_print_pattern (const RSigNode *node) {
	ut32 cur; int i;
	cur = 1 << (node->length - 1);
	for (i = 0; i < node->length; i++) {
		if (node->mask&cur)
			eprintf("..");
		else
			eprintf("%02X", node->match[i]);
		cur >>= 1;
	}
	eprintf("\n");
}

static void r_sig_node_match_buf (unsigned long off, void *buf, unsigned long buf_size, RSigNode *node) {
	unsigned long pos = off;
	ut8 *p = (ut8 *)buf;

	for (pos = 0; pos < buf_size; ) {
		if (r_print_is_interrupted ())
			break;

		if (!r_sig_node_match(p + pos, buf_size - pos, node)) {
			pos += node->length;
			RListIter *it;
			RSigNode *c;

			r_list_foreach(node->child_list, it, c) {
				r_sig_node_match_buf(pos, p, buf_size, c);
			}
			if (node->leaf_list) { 
				RSigLeaf *l;
				r_list_foreach(node->leaf_list, it, l) {
					/*eprintf("@%x %x\n", pos, buf_size); */
					/*r_sig_node_print_pattern(node);*/

					if (l->crc_len) {
						const ut16 crc = crc16(p + pos, l->crc_len);
						eprintf("CRC : %04X CALC : %04X\n", l->crc_val, crc);
						if (crc != l->crc_val)
							continue;
					}

					RListIter *it;
					RSigSubLeaf *s;
					r_list_foreach(l->sub_list, it, s) {
						/*eprintf("flags : %x\n", s->flags);*/
						if (s->flags&1 && p[pos + s->check_off] != s->check_val)
							continue;
						RListIter *it;
						RSigName *n;
						r_list_foreach(s->names_list, it, n) {
							eprintf("%x - %s\n", n->offset, n->name);
						}
					}
				}
				return;
			}
		} else 
			pos += 1;
	}
}

static void r_sig_subleaf_free (RSigSubLeaf *sub) {
	r_list_free(sub->names_list);
}

static void r_sig_leaf_free (RSigLeaf *leaf) {
	leaf->sub_list->free = r_sig_subleaf_free;
	r_list_free(leaf->sub_list);
}

static void r_sig_node_free (RSigNode *node) {
	free(node->maskp);
	free(node->match);

	if (node->leaf_list) {
		node->leaf_list->free = r_sig_leaf_free;
		r_list_free(node->leaf_list);
	}

	if (node->child_list) {
		node->child_list->free = r_sig_node_free;
		r_list_free(node->child_list);
	}
}

static void r_sig_node_print (RSigNode *node, const int indent) {
	int i;
	ut32 cur;
	RListIter *it;
	RSigLeaf *leaf;

	if (!node)
		return;

	for (i = 0; i < indent; i++) eprintf("\t");
	r_sig_node_print_pattern(node);

	r_list_foreach(node->leaf_list, it, leaf) {
		RListIter *it;
		RSigSubLeaf *sub;
		for (i = 0; i < indent; i++) eprintf("\t");
		eprintf("CRC : %04x (%x)\n", leaf->crc_val, leaf->crc_len);
		r_list_foreach(leaf->sub_list, it, sub) {
			RListIter *it;
			RSigName *name;
			eprintf("Flags : %x\n", sub->flags);
			r_list_foreach(sub->names_list, it, name) {
				for (i = 0; i < indent + 1; i++) eprintf("\t");
				eprintf("> %s @ %x\n", name->name, name->offset);
			}
		}
	}

	RSigNode *child;
	r_list_foreach(node->child_list, it, child) {
		r_sig_node_print(child, indent + 1);
	}
}

static void r_sig_parse_leaf (bb *b, RSigNode *node) {
	ut32 flags, off;
	int i;

	node->leaf_list = r_list_new();
	do {
		RSigLeaf *leaf = R_NEW0(RSigLeaf);
		leaf->sub_list = r_list_new();

		leaf->crc_len = read_byte(b);
		leaf->crc_val = read_short(b);

		r_list_append(node->leaf_list, leaf);
		do {
			RSigSubLeaf *sub = R_NEW0(RSigSubLeaf);
			sub->names_list = r_list_new(); 
			r_list_append(leaf->sub_list, sub);

			ut32 length = read_shift(b);

			off = 0;
			do {
				RSigName *name = R_NEW0(RSigName);
				off += read_shift(b);
				name->offset = off;
				ut32 ch = read_byte(b);
				if (ch < 0x20)
					ch = read_byte(b);
				for (i = 0; ch > 0x1f; i++) {
					if (i > R_SIG_NAME_MAX) {
						eprintf("fuckit\n");
						return;
					}
					name->name[i] = (char)ch;
					ch = read_byte(b);
				}
				name->name[i] = '\0';
				flags = ch;
				r_list_append(sub->names_list, name);
			} while(flags&0x01);

			if (flags&0x02) {
				sub->flags |= 1;
				sub->check_off = read_shift(b);
				sub->check_val = read_byte(b);
			}

			if (flags&0x04) {
				sub->flags |= 2;
				ut32 a = read_shift(b);
				ut32 p = read_byte(b);
				if (!p)
					p = read_shift(b);
				b->pos += p;
			}
		} while(flags&0x08); // more terminal nodes
	} while(flags&0x10); // more hash entries
}

static void r_sig_parse_tree (bb *b, RSigNode *root_node) {
	int tree_nodes;
	int i, j;
	ut32 cur;

	tree_nodes = read_shift(b);

	if (!tree_nodes)
		return r_sig_parse_leaf(b, root_node);

	root_node->child_list = r_list_new();

	for (i = 0; i < tree_nodes; i++) {
		RSigNode *node = R_NEW0(RSigNode);
		node->length = read_byte(b);

		/*assert(node->length <= 0x20);*/

		if (node->length >= 0x10)
			node->mask = r_sig_explode_mask(b);
		else
			node->mask = read_shift(b);
		cur = 1 << (node->length - 1);

		node->match = malloc(node->length);
		node->maskp = malloc(node->length);

		j = 0;
		while (cur) {
			node->maskp[j] = (node->mask&cur) ? 0x00 : 0xff;
			node->match[j] = (node->mask&cur) ? 0x00 : read_byte(b);
			j++; cur >>= 1;
		}
		r_list_append(root_node->child_list, node);

		r_sig_parse_tree(b, node);
	}
}

static int r_sig_parse (const RCore *core, const char *path) {
	FILE *fp;
	idasig_t *header = NULL;
	int modules;
	char *name = NULL;
	ut8 *buf = NULL;
	unsigned long size;

	fp = r_sandbox_fopen(path, "rb");
	if (!fp)
		return R_FALSE;

	fseek(fp, 0, SEEK_END);
	size = ftell(fp);
	fseek(fp, 0, SEEK_SET);

	header = R_NEW0(idasig_t);
	if (!header)
		goto err_exit;

	fread(header, 1, sizeof(idasig_t), fp);

	if (memcmp(header->magic, "IDASGN", 6))
		goto err_exit;

	modules = header->modules;

	if (header->version > 5) {
		ut32 tmp;
		if (header->version == 8)
			fseek(fp, 2, SEEK_CUR);
		fread(&tmp, 1, sizeof(ut32), fp);
		/*modules = ntohl(tmp);*/
		modules = tmp;
	}

	name = malloc(header->name_len + 1);
	if (!name)
		goto err_exit;

	fread(name, 1, header->name_len, fp);
	name[header->name_len] = '\0';

	eprintf("Loading %s\n", path);
	eprintf("for %s\n", name);
	eprintf("version %i flags %04x\n", header->version, header->flags);
	eprintf("%i modules\n", modules);

	size -= ftell(fp);

	buf = malloc(size);
	if (!buf)
		goto err_exit;

	fread(buf, 1, size, fp);

	if (header->flags&0x0010)
		goto err_exit;

	RSigNode *node = R_NEW0(RSigNode);
	node->child_list = r_list_new();
	bb *b = init_bb(buf, size);
	r_sig_parse_tree(b, node);
	/*r_sig_node_print(node, -1);*/

	const unsigned int buffer_size = r_io_size (core->io);
	ut8 *buffer = malloc (buffer_size);
	r_io_read_at (core->io, 0L, buffer, buffer_size);
	RListIter *it;
	RSigNode *n;
	r_cons_break(NULL, NULL);
	r_list_foreach(node->child_list, it, n) {
		r_sig_node_match_buf(0L, buffer, buffer_size, n);
	}
	free(buffer);
	r_cons_break_end ();

	r_sig_node_free(node);
	free(buf);
	free(b);

err_exit:
	free(header);
	free(name);
	fclose(fp);
	return R_TRUE;
}

static int r_cmd_test_call(void *user, const char *input) {
	const RCore* core = (RCore*)user;
	return (strncmp(input, "si ", 3)) ? R_FALSE : r_sig_parse(core, input + 3);
}

RCorePlugin r_core_plugin_flair = {
	.name = "fl",
	.desc = "FLAIR loader",
	.license = "Apache",
	.call = r_cmd_test_call,
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_CORE,
	.data = &r_core_plugin_flair
};
#endif
