

#ifndef _GETOPT_H
#define _GETOPT_H 1

# include <ctype.h>

#ifndef DLL_VARIABLE
#define DLL_VARIABLE 
#endif

#ifdef __cplusplus
extern "C" {
#endif


 DLL_VARIABLE char *optarg;

 DLL_VARIABLE int optind;

 DLL_VARIABLE int opterr;

 DLL_VARIABLE int optopt;

/* Describe the long-named options requested by the application.
   The LONG_OPTIONS argument to getopt_long or getopt_long_only is a vector
   of `struct option' terminated by an element containing a name which is
   zero.

   The field `has_arg' is:
   no_argument          (or 0) if the option does not take an argument,
   required_argument    (or 1) if the option requires an argument,
   optional_argument    (or 2) if the option takes an optional argument.

   If the field `flag' is not NULL, it points to a variable that is set
   to the value given in the field `val' when the option is found, but
   left unchanged if the option is not found.

   To have a long-named option do something other than set an `int' to
   a compiled-in constant, such as set a value from `optarg', set the
   option's `flag' field to zero and its `val' field to a nonzero
   value (the equivalent single-letter option character, if there is
   one).  For long options that have a zero `flag' field, `getopt'
   returns the contents of the `val' field.  */

struct option
{
  const char *name;
  /* has_arg can't be an enum because some compilers complain about
     type mismatches in all the code that assumes it is an int.  */
  int has_arg;
  int *flag;
  int val;
};

/* Names for the values of the `has_arg' field of `struct option'.  */

# define no_argument            0
# define required_argument      1
# define optional_argument      2


/* Get definitions and prototypes for functions to process the
   arguments in ARGV (ARGC of them, minus the program name) for
   options given in OPTS.

   Return the option character from OPTS just read.  Return -1 when
   there are no more options.  For unrecognized options, or options
   missing arguments, `optopt' is set to the option letter, and '?' is
   returned.

   The OPTS string is a list of characters which are recognized option
   letters, optionally followed by colons, specifying that that letter
   takes an argument, to be placed in `optarg'.

   If a letter in OPTS is followed by two colons, its argument is
   optional.  This behavior is specific to the GNU `getopt'.

   The argument `--' causes premature termination of argument
   scanning, explicitly telling `getopt' that there are no more
   options.

   If OPTS begins with `-', then non-option arguments are treated as
   arguments to the option '\1'.  This behavior is specific to the GNU
   `getopt'.  If OPTS begins with `+', or POSIXLY_CORRECT is set in
   the environment, then do not permute arguments.  */

DLL_VARIABLE int getopt (int ___argc, char *const *___argv, const char *__shortopts);

DLL_VARIABLE int getopt_long (int ___argc, char * const *___argv,
                        const char *__shortopts,
                        const struct option *__longopts, int *__longind);

DLL_VARIABLE int getopt_long_only (int ___argc, char * const *___argv,
                             const char *__shortopts,
                             const struct option *__longopts, int *__longind);

#ifdef __cplusplus
}
#endif

#endif /* getopt.h */
