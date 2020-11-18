import threading


def debug(msg):
    """ Prints a message to the screen with the name of the current thread
    """

    print("[%s] %s" % (str(threading.currentThread().getName()), msg))


def read_in_chunks(file_object, chunk_size=100):
    """Lazy function (generator) to read a file piece by piece.
    """
    while True:
        data = file_object.read(chunk_size)
        if not data:
            break
        yield data
