{
  'variables': {
  },
  'targets': [
    {
      'target_name': 'libsnmpclient',
      'type': '<(library)',
      'sources': [
        'src/asn1.c',
        'src/snmp.c',
        'src/agent.c',
        'src/client.c',
        'src/crypto.c',
        'src/support.c',
        'src/support.h',
        'src/priv.h',
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
          'defines': [ 'OPENSSL_SYS_WIN32' ],
          'sources': [
            'include/compat/sys/queue.h',
          ],
        }],
        ['"<(without_ssl)" != "false"', {
          'defines': [ ],
          'sources': [
            'src/openssl/OPENSSL-LICENSE',
            'src/openssl/openssl_aes_cfb.c',
            'src/openssl/openssl_aes_core.c',
            'src/openssl/openssl_aes_local.h',
            'src/openssl/openssl_cbc_enc.c',
            'src/openssl/openssl_cfb128.c',
            'src/openssl/openssl_des_enc.c',
            'src/openssl/openssl_des_local.h',
            'src/openssl/openssl_evp.c',
            'src/openssl/openssl_evp_aes.c',
            'src/openssl/openssl_evp_des.c',
            'src/openssl/openssl_evp_local.h',
            'src/openssl/openssl_evp_sha.c',
            'src/openssl/openssl_md32_common.h',
            'src/openssl/openssl_md5.c',
            'src/openssl/openssl_md5_local.h',
            'src/openssl/openssl_modes.h',
            'src/openssl/openssl_rand.c',
            'src/openssl/openssl_set_key.c',
            'src/openssl/openssl_sha1.c',
            'src/openssl/openssl_sha_local.h',
            'src/openssl/openssl_spr.h',
            'src/openssl/compat/openssl_aes.h',
            'src/openssl/compat/openssl_des.h',
            'src/openssl/compat/openssl_evp.h',
            'src/openssl/compat/openssl_md5.h',
            'src/openssl/compat/openssl_sha.h',
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
    {
      'target_name': 'bsnmptools',
      'type': 'executable',
      'dependencies': [
        'libsnmpclient',
      ],
      'sources': [
        'apps/bsnmpimport.c',
        'apps/bsnmpmap.c',
        'apps/bsnmptc.c',
        'apps/bsnmptc.h',
        'apps/bsnmptools.c',
        'apps/bsnmptools.h',
        'apps/main.c',
      ],
      'msvs-settings': {
        'VCLinkerTool': {
          'SubSystem': 1, # /subsystem:console
        },
      },
      'conditions': [
        ['OS == "linux"', {
          'libraries': ['-ldl'],
        }],
        ['OS=="win32" or OS=="win"', {
          'sources': [
             'apps/util.c',
             'apps/getopt.c',
             'apps/getopt.h',
             'apps/getopt1.c',
             'apps/getopt_int.h',
          ],
        }],
        ['OS=="linux" or OS=="freebsd" or OS=="openbsd" or OS=="solaris"', {
          'cflags': [ '--std=c89' ],
          'defines': [ '_GNU_SOURCE' ]
        }],
      ],
      'defines': [ 'BUNDLE=1' ]
    }, # bsnmptools
    {
      'target_name': 'dump_pdu',
      'type': 'executable',
      'dependencies': [
        'libsnmpclient',
      ],
      'sources': [
        'tests/pdu_dump.c',
      ],
      'msvs-settings': {
        'VCLinkerTool': {
          'SubSystem': 1, # /subsystem:console
        },
      },
      'conditions': [
        ['OS == "linux"', {
          'libraries': ['-ldl'],
        }],
        ['OS=="win32" or OS=="win"', {
          'sources': [    ],
        }],
        ['OS=="linux" or OS=="freebsd" or OS=="openbsd" or OS=="solaris"', {
          'cflags': [ '--std=c89' ],
          'defines': [ '_GNU_SOURCE' ]
        }],
      ],
      'defines': [ 'BUNDLE=1' ]
    }, # dump_pdu
  ] # end targets
}
