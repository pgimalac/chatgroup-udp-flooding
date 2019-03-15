NAME = find_a_great_name_to_dont_have_to_type_chatgroup_udp_floating_anymore
FILES = utils.c network.c main.c
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
