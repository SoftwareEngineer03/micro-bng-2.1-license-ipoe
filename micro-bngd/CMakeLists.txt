SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fvisibility=hidden")
ADD_DEFINITIONS(-DPTHREAD_SPINLOCK)

include(GNUInstallDirs)

INCLUDE_DIRECTORIES(include)

IF (MEMDEBUG)
	ADD_DEFINITIONS(-DMEMDEBUG)
	IF (VALGRIND)
		ADD_DEFINITIONS(-DVALGRIND)
	ENDIF (VALGRIND)
ENDIF (MEMDEBUG)

IF (SESSIONID_LEN)
	ADD_DEFINITIONS(-DAP_SESSIONID_LEN=${SESSIONID_LEN})
ELSE (SESSIONID_LEN)
	ADD_DEFINITIONS(-DAP_SESSIONID_LEN=16)
ENDIF (SESSIONID_LEN)

#IF (BACKUP)
#	ADD_DEFINITIONS(-DUSE_BACKUP)
#	ADD_SUBDIRECTORY(backup)
#ENDIF (BACKUP)

IF (NOT DEFINED RADIUS)
	SET(RADIUS TRUE)
ENDIF (NOT DEFINED RADIUS)

IF (LUA)
	IF (LUA STREQUAL "TRUE")
		include(FindLua51)
	ELSE ()
		find_package("Lua" ${LUA})
	ENDIF ()
	IF (NOT DEFINED LUA_VERSION_STRING)
		MESSAGE(FATAL_ERROR "lua not found")
	ENDIF ()
	ADD_SUBDIRECTORY(lua)
ENDIF (LUA)

IF (RADIUS)
	ADD_DEFINITIONS(-DRADIUS)
	ADD_SUBDIRECTORY(radius)
ENDIF (RADIUS)

ADD_SUBDIRECTORY(triton)
ADD_SUBDIRECTORY(vlan-mon)
ADD_SUBDIRECTORY(ctrl)
ADD_SUBDIRECTORY(auth)
ADD_SUBDIRECTORY(logs)
ADD_SUBDIRECTORY(extra)
ADD_SUBDIRECTORY(ipv6)

IF (NOT DEFINED SHAPER)
	SET(SHAPER TRUE)
ENDIF (NOT DEFINED SHAPER)

IF (SHAPER)
	ADD_SUBDIRECTORY(shaper)
ENDIF (SHAPER)

INCLUDE(CheckIncludeFile)
CHECK_INCLUDE_FILE("linux/netfilter/ipset/ip_set.h" HAVE_IPSET)

INCLUDE(CheckFunctionExists)
CHECK_FUNCTION_EXISTS(setns HAVE_SETNS)

INCLUDE (CheckCSourceCompiles)
CHECK_C_SOURCE_COMPILES("
#include <linux/if_link.h>
int main(void)
{
	return IFLA_VRF_UNSPEC+IFLA_VRF_TABLE;
}" HAVE_VRF)

ADD_EXECUTABLE(micro-bngd
	memdebug.c
	session.c
	session_backup.c
	ifcfg.c
	net.c

	backup/backup.c

	ppp/ppp.c
	ppp/ppp_fsm.c
	ppp/ppp_lcp.c
	ppp/lcp_opt_mru.c
	ppp/lcp_opt_magic.c
	ppp/lcp_opt_pcomp.c
	ppp/lcp_opt_accomp.c
	ppp/ppp_auth.c
	ppp/ppp_ipcp.c
	ppp/ipcp_opt_ipaddr.c
	ppp/ipcp_opt_dns.c
	ppp/ipcp_opt_wins.c
	ppp/ipv6cp_opt_intfid.c
	ppp/ppp_ipv6cp.c
	ppp/ppp_ccp.c	
	ppp/ccp_mppe.c
	ppp/dhcpv6.c
	ppp/dhcpv6_packet.c
	ppp/nd.c

	cli/std_cmd.c
	cli/show_sessions.c
	cli/telnet.c
	cli/tcp.c
	cli/cli.c
	
	libnetlink/libnetlink.c
	libnetlink/iputils.c
	libnetlink/genl.c
	libnetlink/ipset.c

	pwdb.c
	ipdb.c

	iprange.c

	utils.c
	rbtree.c
	
	myhashtable.c
	base32.c
	license.c

	vppapi.c

	log.c
	main.c
)

include_directories(/usr/include)
#link_directories(/home/bng/vpp/build-root/install-vpp_debug-native/vpp/lib/x86_64-linux-gnu)
SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -L/usr/lib/x86_64-linux-gnu")

TARGET_LINK_LIBRARIES(micro-bngd triton rt pthread ${crypto_lib} pcre vapiclient vppapiclient vppinfra vlibapi vlibmemoryclient svm check rt m subunit)
set_property(TARGET micro-bngd PROPERTY CMAKE_SKIP_BUILD_RPATH FALSE)
set_property(TARGET micro-bngd PROPERTY CMAKE_BUILD_WITH_INSTALL_RPATH FALSE)
set_property(TARGET micro-bngd PROPERTY INSTALL_RPATH_USE_LINK_PATH FALSE)
set_property(TARGET micro-bngd PROPERTY INSTALL_RPATH ${CMAKE_INSTALL_PREFIX}/lib${LIB_SUFFIX}/micro-bng)

INSTALL(TARGETS micro-bngd
	RUNTIME DESTINATION sbin
)

INSTALL(FILES micro-bng.conf.5 DESTINATION share/man/man5)

IF (NOT DEFINED CPACK_TYPE)
	INSTALL(FILES micro-bng.conf DESTINATION "${CMAKE_INSTALL_SYSCONFDIR}" RENAME micro-bng.conf.dist)

	INSTALL(DIRECTORY DESTINATION "${CMAKE_INSTALL_LOCALSTATEDIR}/log/micro-bng")
	INSTALL(DIRECTORY DESTINATION "${CMAKE_INSTALL_LOCALSTATEDIR}/lib/micro-bng")
ENDIF (NOT DEFINED CPACK_TYPE)

