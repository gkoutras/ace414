#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/fsuid.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
 
void add_rights(char *path, mode_t right) {

	struct stat st;
	mode_t mode;

	stat(path, &st);
	mode = st.st_mode & 0777;
	mode |= right;
	chmod(path, mode);

	return; 
}

void remove_rights(char *path, mode_t right) {

	struct stat st;
	mode_t mode;

	stat(path, &st);
	mode = st.st_mode & 0777;
	mode &= ~(right);
	chmod(path, mode);

	return;
}

void test_multiple_files(void) {

	int i;
	size_t bytes;
	FILE *file;
	char filenames[10][7] = {"file_0", "file_1", 
			"file_2", "file_3", "file_4",
			"file_5", "file_6", "file_7", 		
			"file_8", "file_9"};

	/* example source code */
	for (i = 0; i < 5; i++) {
		file = fopen(filenames[i], "w+");
		if (file == NULL) 
			printf("fopen error\n");
		else {
			bytes = fwrite(filenames[i], strlen(filenames[i]), 1, file);
			fclose(file);
		}
	}

	for (i = 1; i < 5; i+=2) {
		remove_rights(filenames[i], S_IRUSR);
		file = fopen(filenames[i], "r");

		add_rights(filenames[i], S_IRUSR);
		file = fopen(filenames[i], "r");
		fclose(file);
	}

	return;
}

void test_random(void) {

	size_t bytes;
	FILE *file;
	char hello[] = "test\n";

	// test read
	file = fopen("test", "r");

	// test write
	file = fopen("test", "w");
	if (file) {
		fwrite(hello, sizeof(hello)-1, 1, file);
		fclose(file);
	}

	// test read-WRITE
	file = fopen("test", "w+");
	if (file) {
		fwrite(hello, sizeof(hello)-1, 1, file);
		fclose(file);
	}

	// test read-APPEND
	file = fopen("test", "a+");
	if (file) {
		fwrite(hello, sizeof(hello)-1, 1, file);
		fclose(file);
	}

	// test write rights
	remove_rights("test", S_IWUSR);
	file = fopen("test", "w+");
	add_rights("test", S_IWUSR);
	
	
	// test read rights
	remove_rights("test", S_IRUSR);
	file = fopen("test", "r");
	add_rights("test", S_IRUSR);

	return;
}

void test_consecutive_appends(void) {

	int i;
	size_t bytes;
	FILE *file;
	char hello[] = "hello, world!\n";

	// test read-APPEND
	file = fopen("helloworld", "a+");
	if (file) {
		for (i = 0; i < 10; i++) {
			bytes = fwrite(hello, sizeof(hello)-1, 1, file);
		}
		fclose(file);
	}

	return;
}

void test_malicious(void) {

	int i;
	size_t bytes;
	FILE *file;
	char filenames[10][7] = {"file_0", "file_1", 
			"file_2", "file_3", "file_4",
			"file_5", "file_6", "file_7", 		
			"file_8", "file_9"};
	char malicious[] = "malicious\n";

	//test read-APPEND
	for (i = 0; i < 10; i++) {
		file = fopen(filenames[i], "a+");
		if (file) {
			bytes = fwrite(filenames[i], sizeof(malicious)-1, 1, file);
			fclose(file);
		}
	}

	for (i = 0; i < 10; i++) {
		remove_rights(filenames[i], S_IRUSR);
		file = fopen(filenames[i], "r");
		add_rights(filenames[i], S_IRUSR);
	}
	
	return;
}

int main() {
	
	test_multiple_files();

	test_random();

	test_consecutive_appends();

	test_malicious();
		
	return 0;
}
