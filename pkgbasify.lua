#!/usr/libexec/flua

-- SPDX-License-Identifier: BSD-2-Clause
--
-- Copyright(c) 2025 The FreeBSD Foundation.
--
-- This software was developed by Isaac Freund <ifreund@freebsdfoundation.org>
-- under sponsorship from the FreeBSD Foundation.

-- See also the pkgbase wiki page: https://wiki.freebsd.org/PkgBase

function main()
	if already_pkgbase() then
		fatal("The system is already using pkgbase.")
	end
	if not confirm_risk() then
		print("canceled")
		os.exit(1)
	end
	if capture("id -u") ~= "0\n" then
		fatal("This tool must be run as the root user.")
	end

	if not os.execute("pkg bootstrap -y") then
		fatal("failed to bootstrap pkg.")
	end

	create_base_repo_conf()

	if capture("pkg config BACKUP_LIBRARIES") ~= "yes\n" then
		print("Adding BACKUP_LIBRARIES=yes to /usr/local/etc/pkg.conf")
		local f = assert(io.open("/usr/local/etc/pkg.conf", "a"))
		assert(f:write("BACKUP_LIBRARIES=yes\n"))
	end
	
	fetch_parent_for_merge()
	
	if not os.execute("pkg update") then
		fatal("pkg update failed.")
	end

	local packages = select_packages()
	
	-- This is the point of no return, pkg install will start mutating global
	-- system state. Furthermore, pkg install is not necessarily fully atomic,
	-- even if it fails some subset of the packages may have been installed.
	-- This means that we need to fixup the critical password/group related
	-- configuration even if this fails.
	if not os.execute("pkg install -y -r FreeBSD-base " .. table.concat(packages, " ")) then
		err("pkg install failed.")
	end

	-- TODO better handling of .pkgsave files. Take inspiration from freebsd-update here.
	restore_pkgsave("/etc/ssh/sshd_config")
	restore_pkgsave("/etc/master.passwd")
	restore_pkgsave("/etc/group")
	restore_pkgsave("/etc/sysctl.conf")

	if os.execute("service sshd status > /dev/null 2>&1") then
		print("Restarting sshd")
		err_if_fail(os.execute("service sshd restart"))
	end

	err_if_fail(os.execute("pwd_mkdb -p /etc/master.passwd"))
	err_if_fail(os.execute("cap_mkdb /etc/login.conf"))

	-- From https://wiki.freebsd.org/PkgBase:
	-- linker.hints was recreated at kernel install time, when we had .pkgsave files
	-- of previous modules. A new linker.hints file will be created during the next
	-- boot of the OS.
	err_if_fail(os.remove("/boot/kernel/linker.hints"))

	os.exit(0)
end

function already_pkgbase()
	return os.execute("pkg -N > /dev/null 2>&1") and
		os.execute("pkg which /usr/bin/uname > /dev/null 2>&1")
end

function confirm_risk()
	print("Running this tool will irreversibly modify your system to use pkgbase.")
	print("This tool and pkgbase are experimental and may result in a broken system.")
	print("It is highly recommend to backup your system before proceeding.")
	while true do
		io.write("Do you accept this risk and wish to continue? (y/n) ")
		local input = io.read()
		if input == "y" or input == "Y" then
			return true
		elseif input == "n" or input == "N" then
			return false
		end
	end
end

function create_base_repo_conf()
	-- TODO add an option to specify an alternative directory for FreeBSD-base.conf
	-- TODO using grep and test here is not idiomatic lua, improve this
	local conf_dir = "/usr/local/etc/pkg/repos/"
	if not os.execute("pkg config REPOS_DIR | grep " .. conf_dir .. " > /dev/null 2>&1") then
		fatal("non-standard pkg REPOS_DIR config does not include " .. conf_dir)
	end
	local conf_file = conf_dir .. "FreeBSD-base.conf"
	if os.execute("test -e " .. conf_file) then
		fatal(conf_file .. " already exists.")
	end

	print("Creating " .. conf_file)
	assert(os.execute("mkdir -p " .. conf_dir))
	local f = assert(io.open(conf_file, "w"))
	assert(f:write(string.format([[
FreeBSD-base: {
  url: "%s",
  mirror_type: "srv",
  signature_type: "fingerprints",
  fingerprints: "/usr/share/keys/pkg",
  enabled: yes
}
]], base_repo_url())))
end

-- Returns the URL for the pkgbase repository that matches the version
-- reported by freebsd-version(1)
function base_repo_url()
	-- e.g. 15.0-CURRENT, 14.2-STABLE, 14.1-RELEASE, 14.1-RELEASE-p6,
	local raw = capture("freebsd-version")
	local major, minor, branch = assert(raw:match("(%d+)%.(%d+)%-(%u+)"))

	if math.tointeger(major) < 14 then
		fatal("unsupported FreeBSD version: " .. raw)
	end

	if branch == "RELEASE" then
		return "pkg+https://pkg.FreeBSD.org/${ABI}/base_release_" .. minor
	elseif branch == "CURRENT" or branch == "STABLE" then
		return "pkg+https://pkg.FreeBSD.org/${ABI}/base_latest"
	else
		fatal("unsupported FreeBSD version: " .. raw)
	end
end

function fetch_file(url, checksum)
	if not os.execute("fetch " .. url .. "/m/" .. checksum .. ".gz") then
		fatal("fetch failed")
	end
	if not os.execute("gunzip " .. checksum ".gz") then
		fatal("extract failed")
	end
	if capture("sha256 -q " .. checksum):gsub("%s+", "") ~= checksum then
		fatal("checksum mismatch")
	end
end

function fetch_parent_for_merge()
	print("fetching public key")
	-- XXX de-hardcode URL
	local url = "http://update.freebsd.org/14.1-RELEASE/amd64"
	os.remove("pub.ssl")
	if not os.execute("fetch " .. url .. "/pub.ssl") then
		fatal("fetch failed")
	end

	local sha256_expected = "800651ef4b4c71c27e60786d7b487188970f4b4169cc055784e21eb71d410cc5"
	local sha256_actual = capture("sha256 -q pub.ssl"):gsub("%s+", "")
	if sha256_actual ~= sha256_expected then
		fatal("pub.ssl checksum mismatch")
	end
	
	print("fetching tag")
	os.remove("latest.ssl")
	if not os.execute("fetch " .. url .. "/latest.ssl") then
		fatal("fetch failed")
	end

	os.remove("tag.new")
	if not os.execute("openssl pkeyutl -pubin -inkey pub.ssl -verifyrecover	< latest.ssl > tag.new") then
		fatal("verify failed")
	end
	
	local tindexhash = capture("cut -f 5 -d '|' < tag.new"):gsub("%s+", "")
	if not os.execute("fetch " .. url .. "/t/" .. tindexhash) then
		fatal("fetch failed")
	end
	
	if capture("sha256 -q " .. tindexhash):gsub("%s+", "") ~= tindexhash then
		fatal("tindex checksum mismatch")
	end
	
	local index_all = capture("grep " .. tindexhash .. " " .. tindexhash):gsub("%s+", ""):gsub("INDEX%-ALL|")
	fetch_file(index_all)

end

-- Returns a list of pkgbase packages matching the files present on the system
function select_packages()
	local kernel = {}
	local kernel_dbg = {}
	local base = {}
	local base_dbg = {}
	local lib32 = {}
	local lib32_dbg = {}
	local src = {}
	local tests = {}
	
	local rquery = capture("pkg rquery -r FreeBSD-base %n"):gmatch("[^\n]+")
	for package in rquery do
		if package == "FreeBSD-src" or package:match("FreeBSD%-src%-.*") then
			table.insert(src, package)
		elseif package == "FreeBSD-tests" or package:match("FreeBSD%-tests%-.*") then
			table.insert(tests, package)
		elseif package:match("FreeBSD%-kernel%-.*") then
			-- Kernels other than FreeBSD-kernel-generic are ignored
			if package == "FreeBSD-kernel-generic" then
				table.insert(kernel, package)
			elseif package == "FreeBSD-kernel-generic-dbg" then
				table.insert(kernel_dbg, package)
			end
		elseif package:match(".*%-dbg%-lib32") then
			table.insert(lib32_dbg, package)
		elseif package:match(".*%-lib32") then
			table.insert(lib32, package)
		elseif package:match(".*%-dbg") then
			table.insert(base_dbg, package)
		else
			table.insert(base, package)
		end
	end
	assert(#kernel == 1)
	assert(#kernel_dbg == 1)
	assert(#base > 0)
	assert(#base_dbg > 0)
	assert(#lib32 > 0)
	assert(#lib32_dbg > 0)
	assert(#src > 0)
	assert(#tests > 0)

	local selected = {}
	append_list(selected, kernel)
	append_list(selected, base)

	if non_empty_dir("/usr/lib/debug/boot/kernel") then
		append_list(selected, kernel_dbg)
	end
	if os.execute("test -e /usr/lib/debug/lib/libc.so.7.debug") then
		append_list(selected, base_dbg)
	end
	-- Checking if /usr/lib32 is non-empty is not sufficient, as base.txz
	-- includes several empty /usr/lib32 subdirectories.
	if os.execute("test -e /usr/lib32/libc.so.7") then
		append_list(selected, lib32)
	end
	if os.execute("test -e /usr/lib/debug/usr/lib32/libc.so.7.debug") then
		append_list(selected, lib32_dbg)
	end
	if non_empty_dir("/usr/src") then
		append_list(selected, src)
	end
	if non_empty_dir("/usr/tests") then
		append_list(selected, tests)
	end
	
	return selected
end

-- Returns true if the path is a non-empty directory.
-- Returns false if the path is empty, not a directory, or does not exist.
function non_empty_dir(path)
	local p = io.popen("find " .. path .. " -maxdepth 0 -type d -not -empty 2>/dev/null")
	local output = p:read("*a"):gsub("[ \n]", "") -- remove whitespace
	local success = p:close()
	return output ~= "" and success
end

-- Overwrite file with file.pkgsave
function restore_pkgsave(file)
	local ok, err_msg, err_code = os.rename(file .. ".pkgsave", file)
	-- TODO add errno definitions to flua
	local ENOENT = 2
	if not ok and err_code ~= ENOENT then
		err(err_msg)
	end
end

-- Run a command using the OS shell and capture the stdout
-- Does not strip the trailing newline or any other whitespace in the output
-- Asserts that the command exits cleanly
function capture(command)
	local p = io.popen(command)
	local output = p:read("*a")
	assert(p:close())
	return output
end

function append_list(list, other)
	for _, item in ipairs(other) do
		table.insert(list, item)
	end
end

function err_if_fail(ok, err_msg)
	if not ok then
		err(err_msg)
	end
end

function err(msg)
	io.stderr:write("Error: " .. msg .. "\n")
end

function fatal(msg)
	io.stderr:write("Error: " .. msg .. "\n")
	os.exit(1)
end

--main()
os.execute("mkdir -p /tmp/pkgbasify && cd /tmp/pkgbasify")
fetch_parent_for_merge()
