NAME = chat
FILES = utils.c tlv.c network.c innondation.c main.c
FP_FILES = $(addprefix src/, $(FILES))

OBJ = $(FP_FILES:%.c=%.o)
CC = gcc
FLAGS = -g -Wall -Wextra
LIBS =

all: $(NAME)

%.o: %.c
	$(CC) $(FLAGS) -c $? -o $@ $(LIBS)

$(NAME): $(OBJ)
	$(CC) $(FLAGS) $(OBJ) -o $(NAME) $(LIBS)

clean:
	rm -rf $(OBJ)

fclean: clean
	rm -rf $(NAME)

re: fclean all
