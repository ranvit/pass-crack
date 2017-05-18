/**
 * Machine Problem: Password Cracker
 * CS 241 - Fall 2016
 */

#define _XOPEN_SOURCE
#include <crypt.h>
#include <unistd.h>
#include "cracker2.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "utils.h"
#include "queue.h"
#include "format.h"

pthread_mutex_t mtx = PTHREAD_MUTEX_INITIALIZER;
pthread_barrier_t barrier;

typedef struct all_info{
	char i_name[16];
	char i_hash[32];
	char i_partial[32];
	int i_prefix;
	int hash_count;
	char * rec_pass;
	int eof_status;
	int found_status;
	int num_threads;
	char * trial;
	double cpu_sum;
} all_info;

typedef struct breaker_struct{
	pthread_t id;
	int number;
} breaker_struct;

all_info * kendrick;

void * twerk(void * param){

	breaker_struct * miley = (breaker_struct*)param;

	char * replacement = malloc(sizeof(char)*32);
	char * dummy_str;
	char * compare = malloc(sizeof(char)*32);
	int unknown_length = 0;
	long start_index, count_limit;
	int num_hashes = 0;
	int thread_status;
	int other_check;
	double cpu_i, cpu_f;

	struct crypt_data cdata;
	cdata.initialized = 0;

	while(1){

		thread_status = 2;

		pthread_barrier_wait(&barrier);
//__________________________________________________________________________

		if(kendrick->eof_status == EOF) break;

		pthread_barrier_wait(&barrier);
//__________________________________________________________________________

		unknown_length = strlen(kendrick->i_partial) - kendrick->i_prefix;

		getSubrange(unknown_length, kendrick->num_threads, miley->number,
                 &start_index, &count_limit);

		strcpy(replacement, kendrick->i_partial);
		setStringPosition(replacement+kendrick->i_prefix, start_index);

		v2_print_thread_start(miley->number, kendrick->i_name, start_index,
                           replacement);

		num_hashes = 0;

		cpu_i = getThreadCPUTime();

		for(int i = 0; i < (int)count_limit; i++){
			//CHECK IF FOUND BY OTHERS
			pthread_mutex_lock(&mtx);
				other_check = kendrick->found_status;
			pthread_mutex_unlock(&mtx);

			if(other_check == 0){	//gotta cancel
				thread_status = 1;


				break;
			}


			num_hashes++;

//			pthread_mutex_lock(&mtx);
			dummy_str = crypt_r(replacement, "xx", &cdata);
			strcpy(compare, dummy_str);
//			pthread_mutex_unlock(&mtx);

			if(strcmp(kendrick->i_hash, compare) == 0){
//UPDATES
				strcpy(kendrick->rec_pass, replacement);

				pthread_mutex_lock(&mtx);
				kendrick->found_status = 0;
				pthread_mutex_unlock(&mtx);

				thread_status = 0;	//found

				break;
			}

			incrementString(replacement + kendrick->i_prefix);

		}

		cpu_f = getThreadCPUTime();

			pthread_mutex_lock(&mtx);
		kendrick->cpu_sum += (cpu_f - cpu_i);
		v2_print_thread_result(miley->number, num_hashes, thread_status);
			pthread_mutex_unlock(&mtx);

//update hash_count
		pthread_mutex_lock(&mtx);
		kendrick->hash_count += num_hashes;
		pthread_mutex_unlock(&mtx);

		pthread_barrier_wait(&barrier);
//__________________________________________________________________________



	}

	free(replacement);
	free(compare);
	return NULL;
}

int start(size_t thread_count) {

	kendrick = malloc(sizeof(all_info));
	kendrick->hash_count = 0;
	kendrick->cpu_sum = 0;
	kendrick->trial = malloc(sizeof(char)*32);
	kendrick->rec_pass = malloc(sizeof(char)*32);

	pthread_barrier_init (&barrier, NULL, thread_count+1);
	pthread_mutex_init(&mtx, NULL);

	kendrick->num_threads = thread_count;
	kendrick->found_status = -1;

	double initial_time;
	double final_time;
	double init_c;
	double fin_c;


	breaker_struct ** breaker = malloc(sizeof(breaker_struct*)*thread_count);
	for(int i = 0; i < (int)thread_count; i++){
		breaker[i] = malloc(sizeof(breaker_struct));
		breaker[i]->number = i+1;
	}

	for(int i = 0; i < (int)thread_count; i++){
		pthread_create(&(breaker[i]->id), NULL, twerk, (void*)breaker[i]);
	}

	int scan_check;

	char name[16];
	char hash[32];
	char partial[32];
	int prefix = 0;

	while(1){

		kendrick->hash_count = 0;
		kendrick->cpu_sum = 0;

		initial_time = getTime();
		init_c = getThreadCPUTime();

		scan_check = scanf("%s %s %s", name, hash, partial);

//		pthread_mutex_lock(&mtx);
			kendrick->eof_status = scan_check;
//		pthread_mutex_unlock(&mtx);

		kendrick->found_status = 1;

		pthread_barrier_wait(&barrier);
//__________________________________________________________________________

		if(scan_check == EOF) break;

		v2_print_start_user(name);

//		pthread_mutex_lock(&mtx);
			strcpy((kendrick->i_name), name);
			strcpy((kendrick->i_hash), hash);
			strcpy((kendrick->i_partial), partial);

			prefix = (getPrefixLength(kendrick->i_partial));
			kendrick->i_prefix = prefix;
//		pthread_mutex_unlock(&mtx);

		pthread_barrier_wait(&barrier);
//__________________________________________________________________________

//IDLE
		pthread_barrier_wait(&barrier);
//__________________________________________________________________________

		final_time = getTime();
		fin_c = getThreadCPUTime();

		kendrick->cpu_sum += fin_c - init_c;

		v2_print_summary(name, kendrick->rec_pass, kendrick->hash_count,
                      final_time-initial_time, kendrick->cpu_sum, kendrick->found_status);
	}

//JOIN____________

	void * result;
	for(int i = 0; i < (int)thread_count; i++){
		pthread_join(breaker[i]->id, &result);
	}

//JOIN____________



//______________FREES__________________________


	free(kendrick->trial);
	free(kendrick->rec_pass);
	free(kendrick);

	for(int i = 0; i < (int)thread_count; i++){
		free(breaker[i]);
	}
	free(breaker);

	pthread_mutex_destroy(&mtx);
	pthread_barrier_destroy(&barrier);

//______________FREES__________________________

	return 0;
}
