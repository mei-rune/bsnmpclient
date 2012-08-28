{
  'targets': [
    {
      'target_name': 'bsnmptools',
      'type': 'executable',
      'dependencies': [
        'libsnmpclient/libsnmpclient.gyp:libsnmpclient',
      ],
      'sources': [
        'src/bsnmpimport.c',
        'src/bsnmpmap.c',
        'src/bsnmptc.c',
        'src/bsnmptc.h',
        'src/bsnmptools.c',
        'src/bsnmptools.h',
        'src/main.c',
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
             'src/util.c',
             'src/getopt.c',
             'src/getopt.h',
             'src/getopt1.c',
             'src/getopt_int.h',
          ],
        }],
        ['OS=="linux" or OS=="freebsd" or OS=="openbsd" or OS=="solaris"', {
          'cflags': [ '--std=c89' ],
          'defines': [ '_GNU_SOURCE' ]
        }],
      ],
      'defines': [ 'BUNDLE=1' ]
    },
  ],
}
