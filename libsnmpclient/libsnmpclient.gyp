{
  'variables': {
  },
  'targets': [
    {
      'target_name': 'libsnmpclient',
      'type': '<(library)',
      'sources': [
        'asn1.c',
        'snmp.c',
        'agent.c',
        'client.c',
        'crypto.c',
        'support.c',
        'support.h',
        'priv.h',
        'include/bsnmp/config.h',
        'include/bsnmp/asn1.h',
        'include/bsnmp/snmp.h',
        'include/bsnmp/client.h',
        'include/bsnmp/agent.h',
      ],
      'direct_dependent_settings': {
        'include_dirs': [
          'include',
          '<(SHARED_INTERMEDIATE_DIR)',
        ]
      },
      'include_dirs': [
        'include',
        '<(SHARED_INTERMEDIATE_DIR)',
      ],
      'defines': [ ],
      'conditions': [
        ['OS=="linux" or OS=="freebsd" or OS=="openbsd" or OS=="solaris"', {
          'cflags': [ '--std=c89' ],
          'defines': [ '_GNU_SOURCE' ]
        }],
        ['OS=="win32" or OS=="win"', {
          'defines': [ 'OPENSSL_SYS_WIN32' ]
          'sources': [
            'compat/sys/queue.h',
          ],
        }],
        ['"<(without_ssl)" != "false"', {
          'defines': [ ],
          'sources': [
            'openssl/OPENSSL-LICENSE',
            'openssl/openssl_aes_cfb.c',
            'openssl/openssl_aes_core.c',
            'openssl/openssl_aes_local.h',
            'openssl/openssl_cbc_enc.c',
            'openssl/openssl_cfb128.c',
            'openssl/openssl_des_enc.c',
            'openssl/openssl_des_local.h',
            'openssl/openssl_evp.c',
            'openssl/openssl_evp_aes.c',
            'openssl/openssl_evp_des.c',
            'openssl/openssl_evp_local.h',
            'openssl/openssl_evp_sha.c',
            'openssl/openssl_md32_common.h',
            'openssl/openssl_md5.c',
            'openssl/openssl_md5_local.h',
            'openssl/openssl_modes.h',
            'openssl/openssl_rand.c',
            'openssl/openssl_set_key.c',
            'openssl/openssl_sha1.c',
            'openssl/openssl_sha_local.h',
            'openssl/openssl_spr.h',
            'openssl/compat/openssl_aes.h',
            'openssl/compat/openssl_des.h',
            'openssl/compat/openssl_evp.h',
            'openssl/compat/openssl_md5.h',
            'openssl/compat/openssl_sha.h',
          ],   
          'link_settings': {
            'libraries': [
              '-lws2_32.lib',
            ],
          },
        }, {
          'dependencies': [
            'deps/openssl/openssl.gyp:openssl'
          ],
          'export_dependent_settings': [
            'deps/openssl/openssl.gyp:openssl'
          ],
          'defines': [ 'HAS_OPENSSL' ],
        }],
      ],
    }, # end net-snmp
  ] # end targets
}
