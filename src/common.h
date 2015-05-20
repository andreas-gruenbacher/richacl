#ifndef SRC_COMMON_H
#define SRC_COMMON_H

#define COMMON_HELP \
	"ACL entries are represented by colon separated <who>:<mask>:<flags>:<type>\n" \
	"fields. The <who> field may be \"owner@\", \"group@\", \"everyone@\", a user\n" \
	"name or ID, or a group name or ID. Groups have the identifier_group(g) flag\n" \
	"set in the <flags> field. The <type> field may be \"allow\" or \"deny\".\n" \
	"The <mask> and <flags> fields are lists of single-letter abbreviations or\n" \
	"slash-separated names, or a combination of both.\n" \
	"\n" \
	"ACL entry <mask> values are:\n" \
	"\tread_data (r), list_directory (r), write_data (w), add_file (w),\n" \
	"\tappend_data (p), add_subdirectory (p), execute (x), delete_child (d),\n" \
	"\tdelete (D), read_attributes (a), write_attributes (A),\n" \
	"\tread_named_attrs (R), write_named_attrs (W), read_acl (c),\n" \
	"\twrite_acl (C), write_owner(o), synchronize (S),\n" \
	"\twrite_retention (e), write_retention_hold (E)\n" \
	"\n" \
	"ACL entry <flags> values are:\n" \
	"\tfile_inherit (f), dir_inherit (d),\n" \
	"\tno_propagate (n), inherit_only (i),\n" \
	"\tidentifier_group (g), inherited (a)\n" \
	"\n" \
	"ACL flag values are:\n" \
	"\tmasked (m), auto_inherit (a), protected (p), defaulted (d)\n"

bool has_posix_acl(const char *, mode_t mode);
struct richacl *get_richacl(const char *, mode_t);

#endif  /* SRC_COMMON_H */
