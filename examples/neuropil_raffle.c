#include <stdio.h>
#include <string.h>

#include <pthread.h>
#include <sqlite3.h> 

#include "neuropil.h"

#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>

sqlite3 *db = NULL;

static int callback(void *NotUsed, int argc, char **argv, char **azColName) {
	int i;
	for (i = 0; i < argc; i++) {
		printf("%s = %s\r\n", azColName[i], argv[i] ? argv[i] : "NULL");
	}
	printf("\r\n");
	return 0;
}

void open_db() {
	char *zErrMsg = 0;
	int rc;

	rc = sqlite3_open("froscon2018.db", &db);

	if (rc) {
		fprintf(stderr, "Can't open database: %s\r\n", sqlite3_errmsg(db));
	}
}
void init_db() {
	open_db();
	char *zErrMsg = 0;
	int rc;

	char * sql = "CREATE TABLE IF NOT EXISTS MSGS ("               \
		"ID INTEGER PRIMARY KEY AUTOINCREMENT," \
		"DATE CHAR(30) NOT NULL,"                    \
		"MSG          CHAR(500)    NOT NULL,"  \
		"ISSUER         CHAR(64)     NOT NULL);";


	/* Execute SQL statement */
	rc = sqlite3_exec(db, sql, callback, 0, &zErrMsg);

	if (rc != SQLITE_OK) {
		fprintf(stderr, "SQL error: %s\r\n", zErrMsg);
		sqlite3_free(zErrMsg);
	}
	sqlite3_close(db);
}
void write2db(char* msg, char* from) {
	open_db();
	char *zErrMsg = 0;
	int rc;

	char sql[1000] = { 0 };
	sprintf(sql, "INSERT INTO MSGS (DATE,MSG,ISSUER) VALUES (datetime(),\"%s\",\"%s\");", msg, from);

	/* Execute SQL statement */
	rc = sqlite3_exec(db, sql, callback, 0, &zErrMsg);

	if (rc != SQLITE_OK) {
		fprintf(stderr, "SQL error: %s\r\n", zErrMsg);
		sqlite3_free(zErrMsg);
	}
	else {
		fprintf(stdout, "Records created successfully\r\n");
	}
	sqlite3_close(db);
}

char* sanitize(char* target, char* src, int length, bool* result) {
	char* p_s = src;
	char* p_t = target;
	int t;
	*result = true;
	int data_length = length;
	while (data_length > 0) {
		data_length--;
		t = p_s[0];
		if (!(
			t == 0
			//|| t == 32                  // space
			|| (t >= 48 && t < 57)     // 0-9
			//|| (t >= 65 && t <=  90)    // a-z
			//|| (t >= 97 && t <= 122)  // A-Z
			)) {
			//printf("char %d, ", t);
			*result = false;
			t = 32;
		}
		p_t[0] = t;
		p_t++;
		p_s++;
	}

	return target;
}

pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
bool froscon_register_for_hunt(np_context* context, struct np_message* message)
{
	if (message->data_length < 500 && pthread_mutex_lock(&mutex) == 0) {
		char data[500] = { 0 };
		char from[500] = { 0 };
		np_id2str(&message->from, from);
		bool sanitize_result;
		sanitize(data, (char*)message->data, message->data_length, &sanitize_result);
		printf("Received %sregistration: \"%s\" from %s\r\n", sanitize_result ? "" : "invalid ", data, from);
		if (sanitize_result) {
			write2db(data, from);
		}
		char resp[2600] = { 0 };
		snprintf(resp, 2600, "Nachricht \"%s\" erhalten!%s", data, sanitize_result ? "" : " Aber leider ist diese nicht gueltig! (NUR ZAHLEN BITTE!)");
		np_send(context, "FROSCON2018_Response", resp, strnlen(resp, 2599) + 1);
		pthread_mutex_unlock(&mutex);
	}
	return true;
}

int main()
{
	init_db();
	struct np_settings * settings = np_default_settings(NULL);

	snprintf(settings->log_file, 255, "np_raffle_receiver.log");


	np_context* context = np_new_context(settings);
	np_listen(context, "pas6", "localhost", 4444);
	// np_sysinfo_enable_client(context);

	// char* connection_string = np_get_connection_string(context);
	// fprintf(stdout, "My Node: %s\n", connection_string);
	np_join(context, "*:tcp6:demo.neuropil.io:3141");
	np_add_receive_cb(context, "FROSCON2018", froscon_register_for_hunt);

	fprintf(stdout, "Waiting for scavenger hunt registrations...\n");
	while (true) np_time_sleep(np_run(context, 1.0));
}
