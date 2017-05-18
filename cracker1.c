/**
 * Machine Problem: Password Cracker
 * CS 241 - Fall 2016
 */

#define _XOPEN_SOURCE
#include <crypt.h>
#include <unistd.h>
#include "cracker1.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "utils.h"
#include "queue.h"
#include "format.h"

pthread_mutex_t mtx = PTHREAD_MUTEX_INITIALIZER;
int num_rec = 0;
int num_fail = 0;
double time_sum = 0;

typedef struct info{
	char i_name[16];
	char i_hash[32];
	char i_partial[32];
	char * trial;
	int i_prefix;
} info;

typedef struct breaker_struct{
	pthread_t id;
	int number;
	queue_t * i_queue;
} breaker_struct;


void * twerk(void * beyonce){
	char * dummy_str;
	char * compare = malloc(sizeof(char)*32);
	int check = 1;

	int num_hashes = 0;

	struct crypt_data cdata;
	cdata.initialized = 0;

	breaker_struct * miley = (breaker_struct*)beyonce;

	info * kim = (info *)queue_pull(miley->i_queue);

	while(kim){
		num_hashes = 0;
		v1_print_thread_start(miley->number, kim->i_name);

		while(1){
			num_hashes++;
			check = 1;	// to make things werk
			dummy_str = crypt_r(kim->trial, "xx", &cdata);
			strcpy(compare, dummy_str);

			if(strcmp(kim->i_hash, compare) == 0) break;

			check = incrementString(kim->trial + kim->i_prefix);
			if(!check) break;
		}

		if(check){
			pthread_mutex_lock(&mtx);
			num_rec++;
			pthread_mutex_unlock(&mtx);
		}
		else{
			pthread_mutex_lock(&mtx);
			num_fail++;
			pthread_mutex_unlock(&mtx);
		}

		v1_print_thread_result(miley->number, kim->i_name, kim->trial,
	                            num_hashes, getThreadCPUTime(), !check);

		pthread_mutex_lock(&mtx);
		time_sum += getThreadCPUTime();
		pthread_mutex_unlock(&mtx);

		kim = (info *)queue_pull(miley->i_queue);
	}

	free(compare);
	return NULL;
}

int start(size_t thread_count) {

	pthread_mutex_init(&mtx, NULL);

//	double initial_time = getTime();

	char name[16];
	char hash[32];
	char partial[32];
	int prefix = 0;
	long iter = 0;
	char * replacement = malloc(sizeof(char)*32);

	char * compare = malloc(sizeof(char)*32);

//	queue_t * iggy = malloc(sizeof(queue_t));

	queue_t * iggy = queue_create(-1);

	info ** nicki = malloc(sizeof(info*)*20);
	for(int i = 0; i < 20; i++){
		nicki[i] = malloc(sizeof(info));
		(nicki[i])->trial = malloc(sizeof(char)*32);
	}

	breaker_struct ** breaker = malloc(sizeof(breaker_struct*)*thread_count);
	for(int i = 0; i < (int)thread_count; i++){
		breaker[i] = malloc(sizeof(breaker_struct));
		breaker[i]->number = i+1;
		breaker[i]->i_queue = iggy;
	}

//PTHREAD_CREATE??? loop fusion?

	for(int i = 0; i < (int)thread_count; i++){
		pthread_create(&(breaker[i]->id), NULL, twerk, (void*)breaker[i]);
	}

	while(scanf("%s %s %s", name, hash, partial) != EOF){
//		printf("%s %s %s\n", name, hash, partial);

		strcpy((nicki[iter]->i_name), name);
		strcpy((nicki[iter]->i_hash), hash);
		strcpy((nicki[iter]->i_partial), partial);

		prefix = (getPrefixLength(nicki[iter]->i_partial));
		nicki[iter]->i_prefix = prefix;

		strcpy(replacement, nicki[iter]->i_partial);
		setStringPosition(replacement+prefix, 0);
		strcpy((nicki[iter]->trial), replacement);

		queue_push(iggy, (void*)nicki[iter]);
/*
		while(1){


			dummy_str = crypt_r(replacement, "xx", &cdata);
			strcpy(compare, dummy_str);

			if(strcmp(nicki[iter]->i_hash, compare) == 0) break;


			check = incrementString(replacement+prefix);
			if(!check) break;
		}
*/
//		printf("%s %s\n", compare, replacement);
		iter++;
	}

	for(int i = 0; i < (int)thread_count; i++){
		queue_push(iggy, (void*)NULL);
	}

//JOIN____________

	void * result;
	for(int i = 0; i < (int)thread_count; i++){
		pthread_join(breaker[i]->id, &result);
	}

//JOIN____________

//	double final_time = getTime();
	v1_print_summary(num_rec, num_fail);

	queue_destroy(iggy);

//______________FREES__________________________

	for(int i = 0; i < 20; i++){
		free((nicki[i])->trial);
		free(nicki[i]);
	}
	free(nicki);

	free(compare);
	free(replacement);

	for(int i = 0; i < (int)thread_count; i++){
		free(breaker[i]);
	}
	free(breaker);

//	free(iggy);

	pthread_mutex_destroy(&mtx);

//______________FREES__________________________

	return 0;
}
