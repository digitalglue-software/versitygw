package posix

import (
	// "encoding/json"
	"fmt"
	"os/exec"
	"slices"
	"strings"
)

type Perms struct {
	Read bool
	Write bool
	Execute bool
}

type NamedPerms struct {
	Name string
	Perms
}

type Permissions struct {
	// Standard Unix permissions
	User NamedPerms
	Group NamedPerms
	Other Perms
	DefaultUser NamedPerms
	DefaultGroup NamedPerms
	DefaultOther Perms

	// Extended ACLs
	UserAcls []NamedPerms
	GroupAcls []NamedPerms
	DefaultUserAcls []NamedPerms
	DefaultGroupAcls []NamedPerms

	Mask Perms
	DefaultMask Perms
}

/*
Remarks: This function really needs to use the xattr package to get the specific extended attributes.
I have no idea how I can parse the raw output of xatter.Get(), that info seems to be encoded in some way.
This function uses the getfacl command to get the permissions of a file or directory. This is in no way
performant and should be replaced with a more efficient method.

This function is to return both the normal unix permissions and the extended ACLs of a file or directory.
*/
func GetPermissions(path string) (Permissions, error) {
	cmd := exec.Command("/usr/bin/getfacl", path)
	stdout, err := cmd.Output()
	if err != nil {
		fmt.Println(err)
		return Permissions{}, err
	}

	perms := Permissions{}
	lines := strings.Split(string(stdout), "\n")

	// TODO: rewrite this holy crap this is ugly
	for _, line := range lines {
		if strings.HasPrefix(line, "# owner:") {
			// Owner
			n := strings.TrimSpace(strings.Split(line, ":")[1])
			perms.User.Name = n
			perms.DefaultUser.Name = n
		} else if strings.HasPrefix(line, "# group:") {
			// Group
			n := strings.TrimSpace(strings.Split(line, ":")[1])
			perms.Group.Name = n
			perms.DefaultGroup.Name = n
		} else if strings.HasPrefix(line, "user::") {
			// Owner permissions
			perms.User.Perms = PermStringToStruct(strings.TrimSpace(strings.Split(line, "::")[1]))
		} else if strings.HasPrefix(line, "group::") {
			// Group permissions
			perms.Group.Perms = PermStringToStruct(strings.TrimSpace(strings.Split(line, "::")[1]))
		} else if strings.HasPrefix(line, "other::") {
			// Other permissions
			perms.Other = PermStringToStruct(strings.TrimSpace(strings.Split(line, "::")[1]))
		} else if strings.HasPrefix(line, "default:user::") {
			// Default user
			perms.DefaultUser.Perms = PermStringToStruct(strings.TrimSpace(strings.Split(line, "::")[1]))
		} else if strings.HasPrefix(line, "default:group::") {
			// Default group
			perms.DefaultGroup.Perms = PermStringToStruct(strings.TrimSpace(strings.Split(line, "::")[1]))
		} else if strings.HasPrefix(line, "default:other::") {
			// Default other ACL
			perms.DefaultOther = PermStringToStruct(strings.TrimSpace(strings.Split(line, "::")[1]))
		} else if strings.HasPrefix(line, "user:") {
			// Named user ACL
			acl := NamedPerms{}
			acl.Name = strings.TrimSpace(strings.Split(line, ":")[1])
			acl.Perms = PermStringToStruct(strings.TrimSpace(strings.Split(line, ":")[2]))
			perms.UserAcls = append(perms.UserAcls, acl)
		} else if strings.HasPrefix(line, "default:user:") {
			// Named user default ACL
			acl := NamedPerms{}
			acl.Name = strings.TrimSpace(strings.Split(line, ":")[2])
			acl.Perms = PermStringToStruct(strings.TrimSpace(strings.Split(line, ":")[3]))
			perms.DefaultUserAcls = append(perms.DefaultUserAcls, acl)
		} else if strings.HasPrefix(line, "group:") {
			// Named group ACL
			acl := NamedPerms{}
			acl.Name = strings.TrimSpace(strings.Split(line, ":")[1])
			acl.Perms = PermStringToStruct(strings.TrimSpace(strings.Split(line, ":")[2]))
			perms.GroupAcls = append(perms.GroupAcls, acl)
		} else if strings.HasPrefix(line, "default:group:") {
			// Named group default ACL
			acl := NamedPerms{}
			acl.Name = strings.TrimSpace(strings.Split(line, ":")[2])
			acl.Perms = PermStringToStruct(strings.TrimSpace(strings.Split(line, ":")[3]))
			perms.DefaultGroupAcls = append(perms.DefaultGroupAcls, acl)
		} else if strings.HasPrefix(line, "mask::") {
			// Mask ACL
			perms.Mask = PermStringToStruct(strings.TrimSpace(strings.Split(line, "::")[1]))
		} else if strings.HasPrefix(line, "default:mask::") {
			// Default mask ACL
			perms.DefaultMask = PermStringToStruct(strings.TrimSpace(strings.Split(line, "::")[1]))
		}
	}

	// jsonPerms, _ := json.MarshalIndent(perms, "", "  ")
	// fmt.Println("Permissions:", string(jsonPerms))

	return perms, err
}

/*
This function obides by the access check algorithm defined in the POSIX 1003.1e draft 17 "standard".
Psuedocode for the algorithm can be found here:
https://www.usenix.org/legacy/publications/library/proceedings/usenix03/tech/freenix03/full_papers/gruenbacher/gruenbacher_html/main.html
*/
func AccessCheck(username string, groups []string, path string, requestedPerms string) (bool, error) {
	type SelectedPerms struct {
		Type string // "owner", "group", "named_user", "named_group", "other"
		Perms
	}

	type GroupAccess struct {
		GroupOwnerExplicitDenied bool
		NamedGroupExplicidDenied bool
	}

	selected := SelectedPerms{}
	groupAccess := GroupAccess{}

	perms, err := GetPermissions(path)
	if err != nil {
		return false, err
	}

	// Step 1.) Select the ACL entry that most closely matches the requesting process.
	// The ACL entries are looked at in the following order: owner, named users, (owning or named) groups, others.
	// Only a single entry determines access.
	func() {
		if username == perms.User.Name {
			// If the user ID of the process is the owner, the owner entry determines access
			selected.Type = "owner"
			selected.Perms = perms.User.Perms
			return
		} else if i := slices.IndexFunc(perms.UserAcls, func(a NamedPerms) bool { return a.Name == username }); i >= 0 {
			// If the user ID of the process matches the qualifier in one of the named user entries, this entry determines access
			e := perms.UserAcls[i]
			selected.Type = "named_user"
			selected.Perms = e.Perms
			return
		} else if slices.Contains(groups, perms.Group.Name) {
			// If one of the group IDs of the process matches the owning group and the owning group entry
			// contains the requested permissions, this entry determines access
			// Only determines entry if the owning group entry contains the requested permissions
			containsPerms := ContainsPermissions(perms.Group.Perms, requestedPerms)

			if containsPerms {
				selected.Type = "group"
				selected.Perms = perms.Group.Perms
				return
			}

			groupAccess.GroupOwnerExplicitDenied = true
		} else if groups := Intersection(groups, perms.GroupAcls); len(groups) > 0 {
			// If one of the group IDs of the process matches the qualifier of one of the named group entries and this entry
			// contains the requested permissions, this entry determines access
			// Only determines entry if the owning group entry contains the requested permissions
			for _, g := range groups {
				if ContainsPermissions(g.Perms, requestedPerms) {
					selected.Type = "named_group"
					selected.Perms = g.Perms
					return
				}
			}

			groupAccess.NamedGroupExplicidDenied = true
		} else {
			// The other entry determines access.
			selected.Type = "other"
			selected.Perms = perms.Other
		}
	}()

	if groupAccess.GroupOwnerExplicitDenied || groupAccess.NamedGroupExplicidDenied {
		// If one of the group IDs of the process matches the owning group or any of the named group entries, but neither the
		// owning group entry nor any of the matching named group entries contains the requested permissions, this determines that access is denied
		return false, nil
	}

	// Step 2.) Check if the matching entry contains sufficient permissions
	if (selected.Type == "owner" || selected.Type == "other") && ContainsPermissions(selected.Perms, requestedPerms) {
		// If the matching entry resulting from this selection is the owner or other entry and it contains the requested permissions, access is granted
		return true, nil
	} else if
		(selected.Type == "named_user" || selected.Type == "group" || selected.Type == "named_group") &&
		ContainsPermissions(selected.Perms, requestedPerms) &&
		ContainsPermissions(perms.Mask, requestedPerms) {
		// If the matching entry is a named user, owning group, or named group entry and this entry contains the requested permissions
		// and the mask entry also contains the requested permissions (or there is no mask entry), access is granted
		return true, nil
	}

	// Else, access denied
	return false, nil
}

//
// Helpers
//
func PermStringToStruct(perm string) Perms {
	p := Perms{}
	if strings.Contains(perm, "r") {
		p.Read = true
	}
	if strings.Contains(perm, "w") {
		p.Write = true
	}
	if strings.Contains(perm, "x") {
		p.Execute = true
	}
	return p
}

func ContainsPermissions(perms Perms, requestedPerms string) bool {
	if strings.Contains(requestedPerms, "r") && perms.Read {
		return true
	}
	if strings.Contains(requestedPerms, "w") && perms.Write {
		return true
	}
	if strings.Contains(requestedPerms, "x") && perms.Execute {
		return true
	}
	return false
}

func RemoveDups(elements []string)(nodups []string) {
	encountered := make(map[string]bool)
	for _, element := range elements {
		if !encountered[element] {
			nodups = append(nodups, element)
			encountered[element] = true
		}
	}
	return
}

func Intersection(s1 []string, s2 []NamedPerms) (inter []NamedPerms) {
	hash := make(map[string]bool)
	for _, e := range s1 {
		hash[e] = true
	}
	for _, e := range s2 {
		// If elements present in the hashmap then append intersection list.
		if hash[e.Name] {
			inter = append(inter, e)
		}
	}
	return
}
