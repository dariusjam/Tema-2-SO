/**
 * Mangea Liviu Darius 334CA 
 *
 * Operating Sytems 2013 - Assignment 2
 *
 */

#include <assert.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include <fcntl.h>
#include <unistd.h>

#include <errno.h>

#include "utils.h"


#define READ		0
#define WRITE		1

static char *get_word(word_t *s);
static bool shell_cd(word_t *dir);
static int shell_exit();
static char **get_argv(simple_command_t *command, int *size);
static int parse_simple(simple_command_t *s, int level, command_t *father);
static bool do_in_parallel(command_t *cmd1, command_t *cmd2, int level, command_t *father);
static bool do_on_pipe(command_t *cmd1, command_t *cmd2, int level, command_t *father);
int parse_command(command_t *c, int level, command_t *father);
char *read_line();
static int run_simple(simple_command_t *s, command_t *father, char **argv);


/**
 * Internal change-directory command.
 */
static bool shell_cd(word_t *dir)
{
	char *word;
	
	word = get_word(dir);
	return chdir(word);
}

/**
 * Internal exit/quit command.
 */
static int shell_exit()
{
	exit(EXIT_SUCCESS);
}

/**
 * Concatenate parts of the word to obtain the command
 */
static char *get_word(word_t *s)
{
	int string_length = 0;
	int substring_length = 0;

	char *string = NULL;
	char *substring = NULL;

	while (s != NULL) {
		substring = strdup(s->string);

		if (substring == NULL) {
			return NULL;
		}

		if (s->expand == true) {
			char *aux = substring;
			substring = getenv(substring);

			/* prevents strlen from failing */
			if (substring == NULL) {
				substring = calloc(1, sizeof(char));
				if (substring == NULL) {
					free(aux);
					return NULL;
				}
			}

			free(aux);
		}

		substring_length = strlen(substring);

		string = realloc(string, string_length + substring_length + 1);
		if (string == NULL) {
			if (substring != NULL)
				free(substring);
			return NULL;
		}

		memset(string + string_length, 0, substring_length + 1);

		strcat(string, substring);
		string_length += substring_length;

		if (s->expand == false) {
			free(substring);
		}

		s = s->next_part;
	}

	return string;
}

/**
 * Concatenate command arguments in a NULL terminated list in order to pass
 * them directly to execv.
 */
static char **get_argv(simple_command_t *command, int *size)
{
	char **argv;
	word_t *param;

	int argc = 0;
	argv = calloc(argc + 1, sizeof(char *));
	assert(argv != NULL);

	argv[argc] = get_word(command->verb);
	assert(argv[argc] != NULL);

	argc++;

	param = command->params;
	while (param != NULL) {
		argv = realloc(argv, (argc + 1) * sizeof(char *));
		assert(argv != NULL);

		argv[argc] = get_word(param);
		assert(argv[argc] != NULL);

		param = param->next_word;
		argc++;
	}

	argv = realloc(argv, (argc + 1) * sizeof(char *));
	assert(argv != NULL);

	argv[argc] = NULL;
	*size = argc;

	return argv;
}

/**
 * Parse a simple command (internal, environment variable assignment,
 * external command).
 */
static int parse_simple(simple_command_t *s, int level, command_t *father)
{
	char **argv;
	int size;

	argv = get_argv(s, &size);
	
	/* Variabila de mediu */
	if (s->verb != NULL) {
		if (s->verb->next_part != NULL) {
			if (s->verb->next_part->string != NULL && strcmp(s->verb->next_part->string, "=") == 0) {
				return setenv(s->verb->string, s->verb->next_part->next_part->string, 1);
			}
		}
	}
	
	/* If builtin command, execute the command */

	if (strcmp(s->verb->string, "cd") == 0) {
		if (s->out != NULL) {
			creat(s->out->string, S_IREAD | S_IWRITE);
			return shell_cd(s->params);
		}
		return shell_cd(s->params);
	}
	
	if (strcmp(s->verb->string, "exit") == 0 || strcmp(s->verb->string, "quit") == 0) {
		shell_exit();
	}
	
	/*Comanda simpla */
	return run_simple(s,father, argv);
}

static int run_simple(simple_command_t *s, command_t *father, char **argv)
{
	pid_t pid;
	int status;
	int fd_in, fd_out, fd_err;
	
	
	pid = fork();
	
	switch(pid) {
	
	case -1:
		return EXIT_FAILURE;
		
	case 0:

		/*Redirectari catre in, out sau err */
		if (s->in != NULL) {
			fd_in = open(get_word(s->in), O_RDWR | O_CREAT, 0644);
			dup2(fd_in, 0);
			close(fd_in);
		}
		
		if (s->out != NULL && s->io_flags == 0) {
			fd_out = open (get_word(s->out), O_WRONLY | O_CREAT | O_TRUNC, 0644);
			dup2(fd_out, 1);
			close(fd_out);
		}
		
		if (s->out != NULL && s->io_flags == 1) {
			fd_out = open (get_word(s->out), O_WRONLY | O_CREAT | O_APPEND, 0644);
			dup2(fd_out, 1);
			close(fd_out);
		}
		
		if (s->err != NULL && s->io_flags == 0) {
			fd_err = open (get_word(s->err), O_WRONLY | O_CREAT | O_TRUNC, 0644);
			dup2(fd_err, 2);
		}
		
		if (s->err != NULL && s->io_flags == 2) {
			fd_err = open (get_word(s->err), O_WRONLY | O_CREAT | O_APPEND, 0644);
			dup2(fd_err, 2);
		}
		
		if (s->err != NULL && s->out != NULL) {
			dup2(fd_err, 2);
			dup2(fd_out, 1);
		}
		
		close(fd_err);
	
		if (execvp(argv[0], (char *const *) argv) < 0) {
			fprintf(stderr, "Execution failed for '%s'\n", argv[0]);
		}
			
		exit(EXIT_FAILURE);
	
	default:
		if (waitpid(pid, &status, 0) < 0) {
			fprintf(stderr, "Error!\n");
			exit(EXIT_FAILURE);
		}
		
		if (WIFEXITED(status)) {
			return WEXITSTATUS(status);
		}
		break;
	
	}
	
	return status;
}



/**
 * Process two commands in parallel, by creating two children.
 */
static bool do_in_parallel(command_t *cmd1, command_t *cmd2, int level, command_t *father)
{
	/* execute cmd1 and cmd2 simultaneously */
	
	pid_t pid;
	int status;
	int x;
	
	pid = fork();
	
	switch (pid) {
	case -1:
		return EXIT_FAILURE;
	
	case 0:
		return parse_command(cmd1, level + 1, father);
		break;
	
	default:
		x = parse_command(cmd2, level + 1, father);
		
		if (waitpid(pid, &status, 0) < 0) {
			fprintf(stderr, "Error!\n");
			exit(EXIT_FAILURE);
		}
		
		if (WIFEXITED(status)) {
			return WEXITSTATUS(status);
		}
	}

	return x;
}




/**
 * Run commands by creating an anonymous pipe (cmd1 | cmd2)
 */
static bool do_on_pipe(command_t *cmd1, command_t *cmd2, int level, command_t *father)
{
	/* redirect the output of cmd1 to the input of cmd2 */

	pid_t pid;
	int status;
	int filedes[2], x;
	
	pipe(filedes);
	
	pid = fork();
	
	switch (pid) {
	case -1:
		return EXIT_FAILURE;
	
	case 0:
		dup2(filedes[1], STDOUT_FILENO);
		close(filedes[0]);
		parse_command(cmd1, level + 1, father);
		exit(EXIT_SUCCESS);
		
	default:
		dup2(filedes[0], STDIN_FILENO);
		close(filedes[1]);
		
		x = parse_command(cmd2, level + 1, father);
		
		waitpid(pid, &status, 0);
		
		if (WIFEXITED(status)) {
			return WEXITSTATUS(status);
		}
		break;
	}
	
	return x;
}




/**
 * Parse and execute a command.
 */
int parse_command(command_t *c, int level, command_t *father)
{
	int x;

	if (c->op == OP_NONE) {	
		if (c->cmd1 == NULL && c->cmd2 == NULL) {
			return parse_simple(c->scmd, level + 1, c);
		}
		return 0;
	}

	switch (c->op) {
	case OP_SEQUENTIAL:
		parse_command(c->cmd1, level + 1, father);
		return parse_command(c->cmd2, level + 1, c);
		break;

	case OP_PARALLEL:
		return do_in_parallel(c->cmd1, c->cmd2, level + 1, c);
		break;

	case OP_CONDITIONAL_NZERO:
      x = parse_command(c->cmd1, level + 1, c);
		if(x != 0) {
			return parse_command(c->cmd2, level + 1, c);
		}
		return x;      
		break;

	case OP_CONDITIONAL_ZERO:
		x = parse_command(c->cmd1, level + 1, c);
		if(x == 0) {
			return parse_command(c->cmd2, level + 1, c);
		}
		return x;
		break;

	case OP_PIPE:
		return do_on_pipe(c->cmd1, c->cmd2, level + 1, c);
		break;

	default:
		return EXIT_FAILURE;
	}

	return 0;
}

/**
 * Readline from mini-shell.
 */
char *read_line()
{
	char *instr;
	char *chunk;
	char *ret;

	int instr_length;
	int chunk_length;

	int endline = 0;

	instr = NULL;
	instr_length = 0;

	chunk = calloc(CHUNK_SIZE, sizeof(char));
	if (chunk == NULL) {
		fprintf(stderr, ERR_ALLOCATION);
		return instr;
	}

	while (!endline) {
		ret = fgets(chunk, CHUNK_SIZE, stdin);
		if (ret == NULL) {
			break;
		}

		chunk_length = strlen(chunk);
		if (chunk[chunk_length - 1] == '\n') {
			chunk[chunk_length - 1] = 0;
			endline = 1;
		}

		ret = instr;
		instr = realloc(instr, instr_length + CHUNK_SIZE + 1);
		if (instr == NULL) {
			free(ret);
			return instr;
		}
		memset(instr + instr_length, 0, CHUNK_SIZE);
		strcat(instr, chunk);
		instr_length += chunk_length;
	}

	free(chunk);

	return instr;
}

