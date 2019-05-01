NAME = chat

FOLDER_SRC = src/
FOLDER_STRUCTS = src/structs/
FOLDER_ALL = $(FOLDER_SRC) $(FOLDER_STRUCTS)

FILES_SRC = utils.c interface.c base64.c websocket.c onsend.c \
			tlv.c network.c checkers.c flooding.c handlers.c main.c

FILES_STRUCTS = array.c list.c hashmap.c hashset.c

FILES_SRC_FP = $(addprefix $(FOLDER_SRC), $(FILES_SRC))
FILES_STRUCTS_FP = $(addprefix $(FOLDER_STRUCTS), $(FILES_STRUCTS))

FILES_FP = $(FILES_STRUCTS_FP) $(FILES_SRC_FP)

OBJ = $(FILES_FP:%.c=%.o)

CC = gcc
FLAGS = -g -Wall -Wextra -Wno-unused-parameter $(foreach d, $(FOLDER_ALL), -I $(d))
LIBS = -lssl -lcrypto

all: $(NAME)

%.o: %.c
	@echo "Compiling $?"
	@$(CC) $(FLAGS) -c $? -o $@ $(LIBS)

$(NAME): $(OBJ)
	@echo "Build executable $(NAME)"
	@$(CC) $(FLAGS) $(OBJ) -o $(NAME) $(LIBS)
	@echo "Done."

clean:
	@echo "Clean objects"
	@rm -rf $(OBJ)

fclean: clean
	@echo "Clean executable $(NAME)"
	@rm -rf $(NAME)

re: fclean all
