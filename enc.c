#include <string.h>
#include <unistd.h>
#include <glib.h>
#include <pbc.h>
#include <pbc_random.h>

#include "bswabe.h"
#include "common.h"
#include "policy_lang.h"
#include "mpd_policy.h"

char* usage =
"Usage: cpabe-enc [OPTION ...] PUB_KEY FILE [POLICY]\n"
"\n"
"Encrypt FILE under the decryption policy POLICY using public key\n"
"PUB_KEY. The encrypted file will be written to FILE.cpabe unless\n"
"the -o option is used. The original file will be removed. If POLICY\n"
"is not specified, the policy will be read from stdin.\n"
"\n"
"Mandatory arguments to long options are mandatory for short options too.\n\n"
" -h, --help               print this message\n\n"
" -v, --version            print version information\n\n"
" -k, --keep-input-file    don't delete original file\n\n"
" -o, --output FILE        write resulting key to FILE\n\n"
" -d, --deterministic      use deterministic \"random\" numbers\n"
" -x, --xml-file           get the policy attributes from a xml file"
"                          (only for debugging)\n\n"
"";

char* pub_file = 0;
char* in_file  = 0;
char* out_file = 0;
int   keep     = 0;

char* policy = 0;

char** policies = 0;
int policies_counter = 0;
char** files_names = 0;
int files_counter = 0;

void
parse_args( int argc, char** argv )
{
	int i;

    	for( i = 1; i < argc; i++ )
		if(      !strcmp(argv[i], "-h") || !strcmp(argv[i], "--help") )
		{
			printf("%s", usage);
			exit(0);
		}
		else if( !strcmp(argv[i], "-v") || !strcmp(argv[i], "--version") )
		{
			printf(CPABE_VERSION, "-enc");
			exit(0);
		}
		else if( !strcmp(argv[i], "-k") || !strcmp(argv[i], "--keep-input-file") )
		{
			keep = 1;
		}
		else if( !strcmp(argv[i], "-o") || !strcmp(argv[i], "--output") )
		{
			if( ++i >= argc )
				die(usage);
			else
				out_file = argv[i];
		}
		else if( !strcmp(argv[i], "-d") || !strcmp(argv[i], "--deterministic") )
		{
			pbc_random_set_deterministic(0);
		}
        else if( !strcmp(argv[i], "-x") || !strcmp(argv[i], "--xml-input") )
        {
            if( ++i >= argc )
				die(usage);
			else
                parse_xml(argv[i], &policies, &policies_counter, &files_names, &files_counter);
        }
		else if( !pub_file )
		{
			pub_file = argv[i];
		}
		else if( !in_file )
		{
			in_file = argv[i];
		}
		else if( !policy && !policies)
		{
			policy = parse_policy_lang(argv[i]);
		}
		else
			die(usage);

	if( !pub_file || (!in_file && (!policies && !files_names))) {
        die(usage);
    }

	if( !out_file && !files_names)
		out_file = g_strdup_printf("%s.cpabe", in_file);

	if( !policy && !policies)
		policy = parse_policy_lang(suck_stdin());
    
}

int
main( int argc, char** argv )
{
	bswabe_pub_t* pub;
	bswabe_cph_t* cph;
	int file_len;
	GByteArray* plt;
	GByteArray* cph_buf;
	GByteArray* aes_buf;
	element_t m;

	parse_args(argc, argv);
    suck_file(pub_file);
	pub = bswabe_pub_unserialize(suck_file(pub_file), 1);

    if (policies && files_names) {
        int files_to_encrypt, i, file_name_len;

        files_to_encrypt = (policies_counter < files_counter) ? policies_counter : files_counter;
        for (i = 0; i < files_to_encrypt; i++) {
            printf ("[%d] Trying to encrypt file %s.\n", i, files_names[i]);
            policy = parse_policy_lang(policies[i]);
            if( !(cph = bswabe_enc(pub, m, policy)) )
		        die("%s", bswabe_error());
            free(policy);

	        cph_buf = bswabe_cph_serialize(cph);
	        bswabe_cph_free(cph);

            plt = suck_file(files_names[i]);
            file_len = plt->len;
            aes_buf = aes_128_cbc_encrypt(plt, m);
            g_byte_array_free(plt, 1);
            element_clear(m);
            
            file_name_len = strlen(files_names[i]) + 1;
            out_file = malloc(file_name_len * sizeof(char));
            assert(out_file);
            memcpy(out_file, files_names[i], file_name_len);
            strcat(out_file, SUFFIX);

            write_cpabe_file(out_file, cph_buf, file_len, aes_buf);
            printf("[%d] The encypted file is: %s.\n", i, out_file);

	        g_byte_array_free(cph_buf, 1);
	        g_byte_array_free(aes_buf, 1);

            free(out_file);
        }
        
        /* Clean memory */
        for (i = 0; i < policies_counter; i++)
            free(policies[i]);
        free(policies);

        for (i = 0; i < files_counter; i++)
            free(files_names[i]);
        free(files_names);
    } else {
        if( !(cph = bswabe_enc(pub, m, policy)) )
		    die("%s", bswabe_error());
	    free(policy);

	    cph_buf = bswabe_cph_serialize(cph);
	    bswabe_cph_free(cph);

	    plt = suck_file(in_file);
	    file_len = plt->len;
	    aes_buf = aes_128_cbc_encrypt(plt, m);
	    g_byte_array_free(plt, 1);
	    element_clear(m);

	    write_cpabe_file(out_file, cph_buf, file_len, aes_buf);
        
	    g_byte_array_free(cph_buf, 1);
	    g_byte_array_free(aes_buf, 1);
        
        if( !keep )
		    unlink(in_file);
    }
    
	return 0;
}
