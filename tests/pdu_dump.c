// a.cpp : 定义控制台应用程序的入口点。
//


#include <stdio.h>
#include <tchar.h>
#include "bsnmp/config.h"
#include "bsnmp/asn1.h"
#include "bsnmp/snmp.h"

asn_subid_t oid1[] = {1,2,3,4,5,6,7,8,9,10,11,12,13};
asn_subid_t oid2[] = {2,3,4,5,6,7,8,9,10,11,12,13};

void append_bindings(snmp_pdu_t* pdu, asn_subid_t* oid
	, u_int oid_len, enum snmp_syntax syntax ) {

	pdu->bindings[pdu->nbindings].var.len = oid_len;
	memcpy(pdu->bindings[pdu->nbindings].var.subs, oid, oid_len*sizeof(oid[0]));
	pdu->bindings[pdu->nbindings].syntax = syntax;
	pdu->bindings[pdu->nbindings].var.subs[5] = pdu->nbindings + 1;
	pdu->nbindings ++;
}

void dump_pdu(snmp_pdu_t* pdu, enum snmp_version version, u_int type) {
	
    char hextable[] = "0123456789abcdef";

	char buf[10000];
	int i;
	asn_buf_t buffer;
	pdu->version = version;
	pdu->pdu_type = type;
	pdu->request_id = 234;

	append_bindings(pdu, oid1, sizeof(oid1)/sizeof(asn_subid_t), SNMP_SYNTAX_NULL);
	append_bindings(pdu, oid1, sizeof(oid1)/sizeof(asn_subid_t), SNMP_SYNTAX_INTEGER);
	pdu->bindings[pdu->nbindings-1].v.integer = 12;

	append_bindings(pdu, oid1, sizeof(oid1)/sizeof(asn_subid_t), SNMP_SYNTAX_OCTETSTRING);
	pdu->bindings[pdu->nbindings-1].v.octetstring.octets = strdup("1234567890");
	pdu->bindings[pdu->nbindings-1].v.octetstring.len = strlen("1234567890");

	append_bindings(pdu, oid1, sizeof(oid1)/sizeof(asn_subid_t), SNMP_SYNTAX_OID);
	memcpy(pdu->bindings[pdu->nbindings-1].v.oid.subs, oid2, sizeof(oid2));
	pdu->bindings[pdu->nbindings-1].v.oid.len = sizeof(oid2)/sizeof(asn_subid_t);
	
	append_bindings(pdu, oid1, sizeof(oid1)/sizeof(asn_subid_t), SNMP_SYNTAX_IPADDRESS);
	memcpy(pdu->bindings[pdu->nbindings-1].v.ipaddress, "\1\2\3\4", 4);
	append_bindings(pdu, oid1, sizeof(oid1)/sizeof(asn_subid_t), SNMP_SYNTAX_COUNTER);
	pdu->bindings[pdu->nbindings-1].v.uint32 = 2235683;
	append_bindings(pdu, oid1, sizeof(oid1)/sizeof(asn_subid_t), SNMP_SYNTAX_GAUGE);
	pdu->bindings[pdu->nbindings-1].v.uint32 = 1235683;
	append_bindings(pdu, oid1, sizeof(oid1)/sizeof(asn_subid_t), SNMP_SYNTAX_TIMETICKS);
	pdu->bindings[pdu->nbindings-1].v.uint32 = 1235683;
	append_bindings(pdu, oid1, sizeof(oid1)/sizeof(asn_subid_t), SNMP_SYNTAX_COUNTER64);
	pdu->bindings[pdu->nbindings-1].v.counter64 = 12352121212122683;

	snmp_printf("\r\n------------------\r\n");
	snmp_pdu_dump(pdu);
	snmp_printf("\r\n------------------\r\n");
	buffer.asn_len = sizeof(buf);
	buffer.asn_ptr = (u_char*) buf;
	snmp_pdu_encode(pdu, &buffer);

    for(i = 0;i < (buffer.asn_ptr - (u_char*)buf); ++i) {
		char v1 = (buf[i]>>4)&0x0f;
		char v2 = buf[i]&0x0f;
		snmp_printf("%c", hextable[v1]);
		snmp_printf("%c", hextable[v2]);
    }

	snmp_printf("\r\n\r\n");


	
	snmp_pdu_free(pdu);
}

void dump_snmpv1orv2(snmp_pdu_t* pdu, enum snmp_version version, u_int type) {
	snmp_pdu_init(pdu);
	strcpy(pdu->community, "123987");
	dump_pdu(pdu, version, type);
	snmp_pdu_free(pdu);
}


void dump_snmpv3_user(snmp_pdu_t* pdu, u_int type, snmp_user_t* user) {
	snmp_pdu_init(pdu);
	strcpy(pdu->context_name, "testcontextname");
	strcpy((char*)pdu->context_engine, "testcontextengine");
	pdu->context_engine_len = strlen("testcontextengine");
	
	memcpy(pdu->engine.engine_id, "01234567890123456789012345678901234567890123456789",
		SNMP_ENGINE_ID_SIZ);
	pdu->engine.engine_len = SNMP_ENGINE_ID_SIZ;
	pdu->engine.engine_boots = 3;
	pdu->engine.engine_time = 1234;
	pdu->engine.max_msg_size = 10007;

	pdu->security_model = SNMP_SECMODEL_USM;
	
	snmp_auth_to_localization_keys(user, pdu->engine.engine_id, pdu->engine.engine_len);
	snmp_priv_to_localization_keys(user, pdu->engine.engine_id, pdu->engine.engine_len);
	memcpy(&pdu->user, user, sizeof(*user));
	snmp_pdu_init_secparams(pdu);

	dump_pdu(pdu, SNMP_V3, type);
	snmp_pdu_free(pdu);
}


void dump_snmpv3(snmp_pdu_t* pdu, u_int type) {
	snmp_user_t user;
	strcpy(user.sec_name, "meijing");
	user.auth_proto = SNMP_AUTH_NOAUTH;
	user.priv_proto = SNMP_PRIV_NOPRIV;
	dump_snmpv3_user(pdu, type, &user);
	
	user.auth_proto = SNMP_AUTH_HMAC_MD5;
	user.priv_proto = SNMP_PRIV_NOPRIV;
	snmp_set_auth_passphrase(&user, "mfk1234", strlen("mfk1234"));
	snmp_set_priv_passphrase(&user, "mj1234", strlen("mj1234"));
	dump_snmpv3_user(pdu, type, &user);

	user.auth_proto = SNMP_AUTH_HMAC_MD5;
	user.priv_proto = SNMP_PRIV_DES;
	snmp_set_auth_passphrase(&user, "mfk1234", strlen("mfk1234"));
	snmp_set_priv_passphrase(&user, "mj1234", strlen("mj1234"));
	dump_snmpv3_user(pdu, type, &user);

	user.auth_proto = SNMP_AUTH_HMAC_SHA;
	user.priv_proto = SNMP_PRIV_NOPRIV;
	snmp_set_auth_passphrase(&user, "mfk1234", strlen("mfk1234"));
	snmp_set_priv_passphrase(&user, "mj1234", strlen("mj1234"));
	dump_snmpv3_user(pdu, type, &user);
	
	user.auth_proto = SNMP_AUTH_HMAC_SHA;
	user.priv_proto = SNMP_PRIV_AES;
	snmp_set_auth_passphrase(&user, "mfk1234", strlen("mfk1234"));
	snmp_set_priv_passphrase(&user, "mj1234", strlen("mj1234"));
	dump_snmpv3_user(pdu, type, &user);
}

int _tmain(int argc, _TCHAR* argv[])
{
	snmp_pdu_t pdu;
	dump_snmpv1orv2(&pdu, SNMP_V1, SNMP_PDU_GET);
	dump_snmpv1orv2(&pdu, SNMP_V2c, SNMP_PDU_GET);
	dump_snmpv3(&pdu, SNMP_PDU_GET);

	
	return 0;
}

