/*
 * cli_main.c
 *
 *  Created on: Jun 22, 2014
 *      Author: liyixiao
 */

#include <kernel.h>
#include "app.h"
#include "zmodem-toppers.h"
#include "syssvc/serial.h"
#include "fatfs_dri.h"
#include "platform_interface_layer.h"
#include <unistd.h>
#include <ctype.h>
#include <string.h>
#include <t_syslog.h>
#include "gui.h"
#include "csl.h"
#include "mbed-interface.h"
#include "apploader.h"

#include <stdlib.h>
#include <string.h>
#include "sha2_concat.h"

static bool_t load_success;

/**
 * Buffer to store the application module file
 */
static STK_T app_binary_buf[COUNT_STK_T(TMAX_APP_BINARY_SIZE)] __attribute__((nocommon,aligned(SOC_EDMA3_ALIGN_SIZE)));

#if 0
// For debug
push {r0-r3, r12, r14}
mov   r1, r0                    /* 第2引数：texptn */
mov   r0, r3                    /* 第1引数：p_runtsk */
bl debug_exc
pop {r0-r3, r12, r14}
#endif

#if 0 // Legacy code
void load_bootapp() {
	// Open
	static FIL fil;
	FRESULT res = f_open(&fil, BOOTAPP_PATH, FA_READ);
	if (res == FR_NO_FILE) return; // 'bootapp' doesn't exist, do nothing.
	if (res != FR_OK) {
		syslog(LOG_ERROR, "Open boot application '%s' failed, FRESULT: %d", BOOTAPP_PATH, res);
		return;
	}
	syslog(LOG_NOTICE, "Found boot application '%s', start to load.", BOOTAPP_PATH);

	// Read
	char *ptr_c = (void*)app_binary_buf;
	while (1) {
		UINT br;
		res = f_read(&fil, ptr_c, 1, &br);
		assert(res == FR_OK);
		if (br > 0)
			ptr_c += br;
		else
			break;
	}
	res = f_close(&fil);
	assert(res == FR_OK);


#if 0
	FILE *fin = fopen(filepath, "rb");
	while (fread(ptr_c, 1, 1, fin) > 0)
	ptr_c++;
	fclose(fin);
#endif

	SIZE filesz = ptr_c - (char*) app_binary_buf;
	syslog(LOG_NOTICE, "Loading file completed, file size: %d.", filesz);

	ER ercd = load_application(app_binary_buf, filesz);
	if (ercd != E_OK) {
		syslog(LOG_NOTICE, "Load application failed, ercd: %d.", ercd);
		tslp_tsk(500);
	}
}
#endif

static void generate_one_time_password(char* otp, uint32_t otp_size) {
	ulong_t time;
	get_tim(&time);
	srand(time);
	sprintf(otp, "%08d", rand() % 100000000);
}

static int compare_one_time_password(char* otp1, char* otp2, uint32_t otp_size) {	
	syslog(LOG_NOTICE, "\r");
	syslog(LOG_NOTICE, "otp1: %s\r", otp1);
	syslog(LOG_NOTICE, "otp2: %s\r", otp2);

	for(uint32_t i = 0; i < otp_size; ++i) {
		if(otp1[i] < otp2[i]) {
			syslog(LOG_NOTICE, "compare_one_time_password(): return -1\r");
			return -1;
		} else if(otp1[i] > otp2[i]) {
			syslog(LOG_NOTICE, "compare_one_time_password(): return 1\r");
			return 1;
		}
	}

	syslog(LOG_NOTICE, "compare_one_time_password(): return 0\r");
	return 0;
}

static int compare_hash(char* hash1, char* hash2, uint32_t hash_size) {
	char hash1hex[hash_size * 2 + 1];
	char hash2hex[hash_size * 2 + 1];

	for(uint32_t i = 0; i < hash_size; ++i) {
		sprintf(hash1hex + i * 2, "%02x", hash1[i] & 0xFF);
		sprintf(hash2hex + i * 2, "%02x", hash2[i] & 0xFF);
	}

	syslog(LOG_NOTICE, "\r");
	syslog(LOG_NOTICE, "hash1: %s\r", hash1hex);
	syslog(LOG_NOTICE, "hash2: %s\r", hash2hex);

	for(uint32_t i = 0; i < hash_size; ++i) {
		if(hash1[i] < hash2[i]) {
			syslog(LOG_NOTICE, "compare_hash(): return -1\r");
			return -1;
		} else if(hash1[i] > hash2[i]) {
			syslog(LOG_NOTICE, "compare_hash(): return 1\r");
			return 1;
		}
	}
	
	syslog(LOG_NOTICE, "compare_hash(): return 0\r");

	return 0;
}

static void calculate_hash(char* hash, uint32_t hash_size, char* plaintext, uint32_t plaintext_size) {
	SHA256_CTX sha_ctx;
	SHA256_Init(&sha_ctx);
	SHA256_Update(&sha_ctx, plaintext, plaintext_size);
	SHA256_Final(hash, &sha_ctx);

	char log_message[SHA256_DIGEST_LENGTH * 2 + 1];

	for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
		sprintf(log_message + (i * 2), "%02x", hash[i] & 0xFF);
	}
	syslog(LOG_NOTICE, "SHA: %s\r", log_message);
}

static
void test_sd_loader(intptr_t unused) {
#define TMAX_FILE_NUM (100)

	static FILINFO fileinfos[TMAX_FILE_NUM];
	static char    filenames[TMAX_FILE_NUM][_MAX_LFN + 1];
	for (int i = 0; i < TMAX_FILE_NUM; ++i) {
		fileinfos[i].lfname = filenames[i];
		fileinfos[i].lfsize = _MAX_LFN + 1;
	}

	int filenos = 0;

	// Open directory
	static DIR dir;
    FRESULT fres = f_opendir(&dir, SD_APP_FOLDER);
	if (fres != FR_OK) {
		show_message_box("Error", "Open application folder '" SD_APP_FOLDER "' failed.");
//		syslog(LOG_ERROR, "%s(): Open application folder '%s' failed, FRESULT: %d.", __FUNCTION__, SD_APP_FOLDER, fres);
//		tslp_tsk(500);
		return;
	}
//	int dirid = ev3_filesystem_opendir(SD_APP_FOLDER);

	// Read directory
	while (filenos < TMAX_FILE_NUM && f_readdir(&dir, &fileinfos[filenos]) == FR_OK) {
		if (fileinfos[filenos].fname[0] == '\0') // No more file
			break;
		else if (!(fileinfos[filenos].fattrib & AM_DIR)) { // Normal file
			if (fileinfos[filenos].lfname[0] == '\0')
				strcpy(fileinfos[filenos].lfname, fileinfos[filenos].fname);

            // Check extension (hard-coded)
            static const char *non_app_exts[] = { ".rb", ".wav", NULL };
            const char *ext = strrchr(fileinfos[filenos].lfname, '.');
            if (ext != NULL) {
                bool_t not_app = false;
                for (const char **non_app_ext = non_app_exts; *non_app_ext != NULL; non_app_ext++)
                    if (strcasecmp(*non_app_ext, ext) == 0) {
                        not_app = true;
                        break;
                    }
                if (not_app) continue; // ignore this file
            }

			filenos++;
		}
	}
	if (f_closedir(&dir) != FR_OK) {
		show_message_box("Error", "Close application folder '" SD_APP_FOLDER "' failed.");
//		syslog(LOG_ERROR, "%s(): Close application folder '%s' failed.", __FUNCTION__, SD_APP_FOLDER);
//		tslp_tsk(500);
		return;
	}
#if 0
	while (filenos < TMAX_FILE_NUM && ev3_filesystem_readdir(dirid, &fileinfos[filenos]) == E_OK) {
		if (fileinfos[filenos].fname[0] != '\0') {
			filenos++;
		} else break;
	}
	ev3_filesystem_closedir(dirid);
#endif

	static CliMenuEntry entry_tab[TMAX_FILE_NUM + 1];
	for (int i = 0; i < filenos; ++i) {
		entry_tab[i].key = '1' + i;
		entry_tab[i].title = fileinfos[i].lfname;
		entry_tab[i].exinf = i;
	}
	entry_tab[filenos].key = 'Q';
	entry_tab[filenos].title = "Cancel";
	entry_tab[filenos].exinf = -1;

	static CliMenu climenu = {
		.title     = "EV3RT App Loader",
		.msg       = "Select app:",
		.entry_tab = entry_tab,
		.entry_num = sizeof(entry_tab) / sizeof(CliMenuEntry),
	};
	climenu.entry_num = filenos + 1;

	static char filepath[256 * 2];
	while(1) {
		fio_clear_screen();
		show_cli_menu(&climenu);
		const CliMenuEntry* cme = select_menu_entry(&climenu);
		if(cme != NULL) {
			switch(cme->exinf) {
			case -1:
				return;

			default: {
				strcpy(filepath, SD_APP_FOLDER);
				strcat(filepath, "/");
				strcat(filepath, fileinfos[cme->exinf].lfname);

				syslog(LOG_NOTICE, "Start to load the application file '%s'.", filepath);

				// Open
				static FIL fil;
				FRESULT res = f_open(&fil, filepath, FA_READ);
				assert(res == FR_OK);

				// Read
                uint32_t filesz = f_size(&fil);
                if (filesz > TMAX_APP_BINARY_SIZE) {
					show_message_box("Error", "Application is too large.");
                    return;
                }

				UINT br;
				res = f_read(&fil, app_binary_buf, filesz, &br);
                assert(res == FR_OK);
                assert(br == filesz);

				res = f_close(&fil);
				assert(res == FR_OK);

				syslog(LOG_NOTICE, "Loading file completed, file size: %d.", filesz);

				ER ercd = load_application(app_binary_buf, filesz);
				if (ercd == E_OK) {
					load_success = true;
					return;
                } else if (ercd == E_NOSPT) {
					show_message_box("Error", "App ver. before\n"PIL_VERSION_STRING" must be\nrecompiled.");
				} else {
					syslog(LOG_NOTICE, "Load application failed, ercd: %d.", ercd);
					show_message_box("Error", "Failed to load application.");
//					tslp_tsk(500);
				}
			}
			}
		}
	}
}

static
void test_serial_loader(intptr_t portid) {
	ER   ercd;
	SIZE filesz;

	syslog(LOG_NOTICE, "Start to receive an application file using ZMODEM protocol.");
	platform_pause_application(false); // Ensure the priority of Bluetooth  task
	ercd = zmodem_recv_file(portid, app_binary_buf, sizeof(app_binary_buf), &filesz);
	platform_pause_application(true); // Ensure the priority of Bluetooth  task

	if (ercd != E_OK) {
		syslog(LOG_NOTICE, "Receiving file failed, ercd: %d.", ercd);
		show_message_box("Error", "Receiving application file failed.");
//		tslp_tsk(500);
		return;
	}

	syslog(LOG_NOTICE, "Receiving file completed, file size: %d bytes", filesz);
	show_message_box("App Received", "Click the CENTER button to run.");

	ercd = load_application(app_binary_buf, filesz);
	if (ercd == E_OK) {
		load_success = true;
	} else {
		syslog(LOG_NOTICE, "Load application failed, ercd: %d.", ercd);
		show_message_box("Error", "Failed to load application.");
//		tslp_tsk(500);
	}
}

static
void test_bluetooth_pan_loader(intptr_t portid) {
    const char *file_name;
    uint32_t    file_size;

	/**
	 * Draw GUI
	 */
	font_t *font = global_brick_info.font_w10h16;
	bitmap_t *screen = global_brick_info.lcd_screen;
	int offset_y = 0;
	bitmap_bitblt(NULL, 0, 0, screen, 0, offset_y, screen->width, font->height * 2, ROP_CLEAR); // Clear
	bitmap_bitblt(NULL, 0, 0, screen, 0, offset_y, screen->width, font->height, ROP_SET); // Clear
	bitmap_draw_string("Receive App File", screen, (screen->width - strlen("Receive App File") * font->width) / 2, offset_y, font, ROP_COPYINVERTED);
	offset_y += font->height * 2;
	bitmap_bitblt(NULL, 0, 0, screen, 0, offset_y, screen->width, screen->height, ROP_CLEAR); // Clear
	bitmap_draw_string("BT PAN IP Addr.:", screen, 0, offset_y, font, ROP_COPY);
	offset_y += font->height * 2;
	bitmap_draw_string(ev3rt_bluetooth_ip_address, screen, 0, offset_y, font, ROP_COPY);
	offset_y += font->height * 2;
//    syslog(LOG_NOTICE, "%s", cm->title);


	platform_pause_application(false); // Ensure the priority of Bluetooth task

    httpd_receive_file_start(app_binary_buf, TMAX_APP_BINARY_SIZE);
    while(!global_brick_info.button_pressed[BRICK_BUTTON_BACK]) {
        tslp_tsk(100);
        if (http_receive_file_poll(&file_name, &file_size)) { // File received
            syslog(LOG_NOTICE, "File '%s' (%lu bytes) is received.", file_name, file_size);
            if (strcmp("", file_name) == 0) { // uImage received
                apploader_store_file("/uImage", app_binary_buf, file_size);
	            show_message_box("uImage Received", "Please restart  EV3 to use it.");
            } else { // User application received
    	        static char filepath[1024/* TODO: check length? */];
    	        strcpy(filepath, "/ev3rt/apps"/*SD_APP_FOLDER*/);
    	        strcat(filepath, "/");
    	        strcat(filepath, file_name);
                apploader_store_file(filepath, app_binary_buf, file_size);
	            show_message_box("App Received", "Click the CENTER button to run.");
                if (!load_application(app_binary_buf, file_size) == E_OK) break; // goto cancel
                load_success = true;
            }
            return;
        }
    }

    // Cancel
    while(global_brick_info.button_pressed[BRICK_BUTTON_BACK]);
    httpd_receive_file_start(NULL, 0);
	show_message_box("Error", "Failed to load application.");
}

static
void test_bluetooth_pan_loader_secure_update(intptr_t portid) {
    const char *file_name;
    uint32_t    file_size;

	uint32_t otp_size = 8;
    char otp[otp_size + 1];
    generate_one_time_password(otp, otp_size);
    char msg_otp[25];
    sprintf(msg_otp, "One-Time Password: %s", otp);
    show_message_box("Secure Update", msg_otp);

	/**
	 * Draw GUI
	 */
	font_t *font = global_brick_info.font_w10h16;
	bitmap_t *screen = global_brick_info.lcd_screen;
	int offset_y = 0;
	bitmap_bitblt(NULL, 0, 0, screen, 0, offset_y, screen->width, font->height * 2, ROP_CLEAR); // Clear
	bitmap_bitblt(NULL, 0, 0, screen, 0, offset_y, screen->width, font->height, ROP_SET); // Clear
	bitmap_draw_string("Receive App File", screen, (screen->width - strlen("Receive App File") * font->width) / 2, offset_y, font, ROP_COPYINVERTED);
	offset_y += font->height * 2;
	bitmap_bitblt(NULL, 0, 0, screen, 0, offset_y, screen->width, screen->height, ROP_CLEAR); // Clear
	bitmap_draw_string("BT PAN IP Addr.:", screen, 0, offset_y, font, ROP_COPY);
	offset_y += font->height * 2;
	bitmap_draw_string(ev3rt_bluetooth_ip_address, screen, 0, offset_y, font, ROP_COPY);
	offset_y += font->height * 2;
//    syslog(LOG_NOTICE, "%s", cm->title);


	platform_pause_application(false); // Ensure the priority of Bluetooth task

    httpd_receive_file_start(app_binary_buf, TMAX_APP_BINARY_SIZE);
    while(!global_brick_info.button_pressed[BRICK_BUTTON_BACK]) {
        tslp_tsk(100);
        if (http_receive_file_poll(&file_name, &file_size)) { // File received
            syslog(LOG_NOTICE, "File '%s' (%lu bytes) is received.", file_name, file_size);
            if (strcmp("", file_name) == 0) { // uImage received
            	char   received_hash[SHA256_DIGEST_LENGTH];
            	char calculated_hash[SHA256_DIGEST_LENGTH];

            	// ファイルサイズがハッシュ長より小さいのはおかしい。処理もバグるので終了
            	if(file_size < SHA256_DIGEST_LENGTH) {
            		show_message_box("Secure Update", "File size is too small.");
            		break;
            	} else {
            		show_message_box("Secure Update", "File size is valid.");
            	}

            	uint32_t   hash_size = SHA256_DIGEST_LENGTH;
            	uint32_t binary_size = file_size - hash_size - otp_size;

            	syslog(LOG_NOTICE, "   otp_size = %lu\r", otp_size);
            	syslog(LOG_NOTICE, "  hash_size = %lu\r", hash_size);
            	syslog(LOG_NOTICE, "binary_size = %lu\r", binary_size);

            	/* received_hash[] に、受信したファイル中に格納されているハッシュ値を格納 */
            	char* buf_char_pointer = (char *)app_binary_buf;
            	for(uint32_t i = 0; i < hash_size; ++i) {
            		received_hash[i] = buf_char_pointer[binary_size + i];
            	}

            	/* 受診したバイナリファイルのハッシュ値を計算し、受信したハッシュ値と比較 */
            	calculate_hash(calculated_hash, hash_size, (char *)app_binary_buf, binary_size);
            	if(compare_hash(calculated_hash, received_hash, hash_size) != 0) {
            		show_message_box("Secure Update", "Hash value is invalid.");
            		break;
            	} else {
            		show_message_box("Secure Update", "Hash value is valid.");
            	}

            	/* received_otp[] に、受信したワンタイムパスワードを格納 */
            	char received_otp[otp_size + 1];
            	for(uint32_t i = 0; i < otp_size; ++i) {
            		received_otp[i] = buf_char_pointer[i + binary_size + hash_size];
            	}
            	received_otp[otp_size] = '\0';
            	syslog(LOG_NOTICE, "received_otp = \"%s\"\r", received_otp);

            	/* ワンタイムパスワードを比較 */
            	if( compare_one_time_password(otp, received_otp, otp_size) != 0 ) {
            		show_message_box("Secure Update", "One-Time Password is wrong.");
            		break;
            	} else {
            		show_message_box("Secure Update", "One-Time Password is correct.");
            	}

                apploader_store_file("/uImage", app_binary_buf, binary_size); // ハッシュ部分は無視
	            show_message_box("uImage Received", "Please restart  EV3 to use it.");
            } else { // User application received
    	        static char filepath[1024/* TODO: check length? */];
    	        strcpy(filepath, "/ev3rt/apps"/*SD_APP_FOLDER*/);
    	        strcat(filepath, "/");
    	        strcat(filepath, file_name);
                apploader_store_file(filepath, app_binary_buf, file_size);
	            show_message_box("App Received", "Click the CENTER button to run.");
                if (!load_application(app_binary_buf, file_size) == E_OK) break; // goto cancel
                load_success = true;
            }
            return;
        }
    }

    // Cancel
    while(global_brick_info.button_pressed[BRICK_BUTTON_BACK]);
    httpd_receive_file_start(NULL, 0);
	show_message_box("Error", "Failed to load application.");
}

static void sha_test(intptr_t portid) {
	char *message = {"Sample Message"};
	unsigned char digest[SHA256_DIGEST_LENGTH];
	
	SHA256_CTX sha_ctx;
	SHA256_Init(&sha_ctx); // コンテキストを初期化
	SHA256_Update(&sha_ctx, message, strlen(message)); // message を入力にする
	SHA256_Final(digest, &sha_ctx); // digest に出力

	syslog(LOG_NOTICE, "message = %s\r", message);
	
	syslog(LOG_NOTICE, "SHA256: \r");
	for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
		syslog(LOG_NOTICE, "%02x", digest[i]);
	}
	syslog(LOG_NOTICE, "\r\n");
}

static const CliMenuEntry entry_tab[] = {
	{ .key = '1', .title = "SD card", .handler = test_sd_loader },
	{ .key = '2', .title = "Bluetooth PAN", .handler = test_bluetooth_pan_loader },
	{ .key = '3', .title = "Bluetooth SPP", .handler = test_serial_loader, .exinf = SIO_PORT_BT },
	{ .key = '4', .title = "Secure Update", .handler = test_bluetooth_pan_loader_secure_update },
	{ .key = '5', .title = "SHA Test", .handler = sha_test },
//	{ .key = '3', .title = "Serial port 1", .handler = test_serial_loader, .exinf = SIO_PORT_UART  },
//	{ .key = 'D', .title = "Download Application", },
	{ .key = 'Q', .title = "Exit to console", .handler = NULL },
};

const CliMenu climenu_main = {
	.title     = "EV3RT App Loader",
	.msg       = "Load app from:",
	.entry_tab = entry_tab,
	.entry_num = sizeof(entry_tab) / sizeof(CliMenuEntry),
};

ER application_load_menu() {
	load_success = false;
	show_cli_menu(&climenu_main);
	const CliMenuEntry *cme = select_menu_entry(&climenu_main);
	if(cme != NULL && cme->handler != NULL) {
		if (try_acquire_mmcsd() == E_OK) {
			cme->handler(cme->exinf);
			if (load_success) return E_OK; // MMCSD will be released on unloading
			release_mmcsd();
		} else {
			show_message_box("Error", "Please eject USB");
		}
	}
	return E_PAR;
}
