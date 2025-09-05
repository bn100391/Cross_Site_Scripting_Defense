#include "mongoose.h"

const char header[] = "Set-Cookie: password=REDACTED; HttpOnly; Strict - Transport - Security : max - age =15552000; Content - Security - Policy : default-src ’self’\r\n";
const char get[] = "<html>" " <head>" "  <title>fixxss: get response</title>" " </head>" " <body>" "  <p>%s</p>" "  <form action='/put' method='post'>" "   <label for='data'>New data:</label>" "   <input type='text' id='data' name='data'/>" "  </form>" "  <p>(Press enter to store.)</p>" " </body>" "</html>";
const char put[] = "<html>" " <head>" "  <title>fixxss: put response</title>" " </head>" " <body>" "  <p>Data stored.</p>" "  <p><a href='/get'>Click</a> to continue.</p>" " </body>" "</html>";
const char err[] = "<html>" " <head>" "  <title>fixxss: error response</title>" " </head>" " <body>" "  <p>illegal input</p>" " </body>" "</html>";

char data[BUFSIZ] = { 0 };
char safe_data[BUFSIZ] = { 0 };


/**
 * This function determines whether or not a character is part of the list of ones that are allowed.   
 * 
 * @param symbol 
 * @return 0 if allowed, -1 if not allowed. 
 * 
 */

int isAllowed(char *symbol)
{
	int result = -1;

	if (*symbol == '.' || *symbol == ',' || *symbol == '!' || *symbol == '?' || *symbol == ' ' || *symbol == '\0') {
		result = 0;
	}

	char capLetter[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
	char letter[] = "abcdefghijklmnopqrstuvwxyz";
	char number[] = "0123456789";

	if (result != 0) {
		for (int a = 0; a < strlen(capLetter); a++) {
			if (*symbol == capLetter[a]) {
				result = 0;
				break;
			}
		}
	}


	if (result != 0) {
		for (int b = 0; b < strlen(letter); b++) {
			if (*symbol == letter[b]) {
				result = 0;
				break;
			}
		}
	}


	if (result != 0) {
		for (int c = 0; c < strlen(number); c++) {
			if (*symbol == number[c]) {
				result = 0;
				break;
			}
		}
	}


	return result;
}


/**
 * This functions walks each symbol in source buffer, and if they are allowed, writes them to the sanitized buffer 
 * 
 * @param source source buffer, MUST BE SAME SIZE AS SAFE BUFFER
 * @param san_buf buffer containing whitelisted data, MUST BE SAME SIZE AS SOURCE BUFFER
 * @param source_size the size of the source buffer
 * @return -1 if there were symbols in the source buffer that are not allowed, 0 if there were not. 
 * 
 */
int whitelist(char *source, int source_size, char *san_buf)
{
	if (sizeof(source) != sizeof(san_buf)) {
		perror("ERROR: Source buffer and sanitized buffer are not the same size\n");
		exit(1);
	}

	int r_val = 0;

	int san_index = 0;
	for (int i = 0; i < source_size; i++) {
		if (isAllowed(source + i) == 0) {
			char *c = memcpy(san_buf + san_index, source + i, 1);
			if (c = NULL) {
				perror("Error reading from source buffer\n");
				exit(1);
			}
			san_index++;
		} else {
			r_val = -1;
			continue;
		}

	}

	return r_val;
}



static void cb(struct mg_connection *c, int ev, void *ev_data, void *unused)
{
	if (ev == MG_EV_HTTP_MSG) {
		struct mg_http_message *hm = (struct mg_http_message *) ev_data;
		LOG(LL_INFO, ("New request to: [%.*s]", (int) hm->uri.len, hm->uri.ptr));

		if (mg_http_match_uri(hm, "/put")) {
			int rc;

			rc = mg_http_get_var(&hm->body, "data", data, sizeof data);
			if (rc <= 0) {
				const char *msg = "could not read data";
				LOG(LL_ERROR, (msg));
				mg_http_reply(c, 400, header, err, msg);
				return;
			}

			int result = whitelist(data, sizeof(data), safe_data);
			if (result != 0) {
				//XSS found, write the error messages.
				mg_http_reply(c, 400, header, err);
				LOG(LL_INFO, ("illegal input"));
			}

			LOG(LL_INFO, ("received %s", safe_data));

			mg_http_reply(c, 200, header, put);
		} else {
			mg_http_reply(c, 200, header, get, safe_data);
		}
	}
}


int main(int argc, char *argv[])
{
	struct mg_mgr mgr;
	int exitcode = EXIT_FAILURE;
	char address[7];

	if (argc != 2) {
		fprintf(stderr, "usage: %s PORT\n", argv[0]);
		goto done;
	}

	snprintf(address, sizeof address, ":%s", argv[1]);

	mg_mgr_init(&mgr);
	mg_log_set("2");
	mg_http_listen(&mgr, address, cb, NULL);

	for (;;) {
		mg_mgr_poll(&mgr, 50);
	}

	mg_mgr_free(&mgr);

  done:
	exit(exitcode);
}
