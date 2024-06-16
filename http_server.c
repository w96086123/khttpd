#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/kthread.h>
#include <linux/sched/signal.h>
#include <linux/tcp.h>

#include "http_server.h"


#define HTTP_RESPONSE_200_DUMMY                               \
    ""                                                        \
    "HTTP/1.1 200 OK" CRLF "Server: " KBUILD_MODNAME CRLF     \
    "Content-Type: text/plain" CRLF "Content-Length: 12" CRLF \
    "Connection: Close" CRLF CRLF "Hello World!" CRLF
#define HTTP_RESPONSE_200_KEEPALIVE_DUMMY                     \
    ""                                                        \
    "HTTP/1.1 200 OK" CRLF "Server: " KBUILD_MODNAME CRLF     \
    "Content-Type: text/plain" CRLF "Content-Length: 12" CRLF \
    "Connection: Keep-Alive" CRLF CRLF "Hello World!" CRLF
#define HTTP_RESPONSE_501                                              \
    ""                                                                 \
    "HTTP/1.1 501 Not Implemented" CRLF "Server: " KBUILD_MODNAME CRLF \
    "Content-Type: text/plain" CRLF "Content-Length: 21" CRLF          \
    "Connection: Close" CRLF CRLF "501 Not Implemented" CRLF
#define HTTP_RESPONSE_501_KEEPALIVE                                    \
    ""                                                                 \
    "HTTP/1.1 501 Not Implemented" CRLF "Server: " KBUILD_MODNAME CRLF \
    "Content-Type: text/plain" CRLF "Content-Length: 21" CRLF          \
    "Connection: KeepAlive" CRLF CRLF "501 Not Implemented" CRLF
#define SEND_HTTP_MSG(socket, buf, format, ...)           \
    snprintf(buf, SEND_BUFFER_SIZE, format, __VA_ARGS__); \
    http_server_send(socket, buf, strlen(buf))

#define RECV_BUFFER_SIZE 4096
#define SEND_BUFFER_SIZE 256
#define BUFFER_SIZE 256

extern struct workqueue_struct *khttpd_wq;

struct http_request {
    struct socket *socket;
    enum http_method method;
    char request_url[128];
    int complete;
    struct dir_context dir_context;
    struct list_head node;
    struct work_struct khttpd_work;
};


static int http_server_recv(struct socket *sock, char *buf, size_t size)
{
    struct kvec iov = {.iov_base = (void *) buf, .iov_len = size};
    struct msghdr msg = {.msg_name = 0,
                         .msg_namelen = 0,
                         .msg_control = NULL,
                         .msg_controllen = 0,
                         .msg_flags = 0};
    return kernel_recvmsg(sock, &msg, &iov, 1, size, msg.msg_flags);
}

static int http_server_send(struct socket *sock, const char *buf, size_t size)
{
    struct msghdr msg = {.msg_name = NULL,
                         .msg_namelen = 0,
                         .msg_control = NULL,
                         .msg_controllen = 0,
                         .msg_flags = 0};
    int done = 0;
    while (done < size) {
        struct kvec iov = {
            .iov_base = (void *) ((char *) buf + done),
            .iov_len = size - done,
        };
        int length = kernel_sendmsg(sock, &msg, &iov, 1, iov.iov_len);
        if (length < 0) {
            pr_err("write error: %d\n", length);
            break;
        }
        done += length;
    }
    return done;
}


static void catstr(char *res, char *first, char *second)
{
    int first_size = strlen(first);
    int second_size = strlen(second);
    memset(res, 0, BUFFER_SIZE);
    memcpy(res, first, first_size);
    memcpy(res + first_size, second, second_size);
}

static inline int read_file(struct file *fp, char *buf)
{
    return kernel_read(fp, buf, fp->f_inode->i_size, 0);
}

// callback for 'iterate_dir', trace entry.
static bool tracedir(struct dir_context *dir_context,
                     const char *name,
                     int namelen,
                     loff_t offset,
                     u64 ino,
                     unsigned int d_type)
{
    if (strcmp(name, ".")) {
        struct http_request *request =
            container_of(dir_context, struct http_request, dir_context);
        char buf[SEND_BUFFER_SIZE] = {0};
        char *url =
            !strcmp(request->request_url, "/") ? "" : request->request_url;

        SEND_HTTP_MSG(request->socket, buf,
                      "%lx\r\n<tr><td><a href=\"%s/%s\">%s</a></td></tr>\r\n",
                      34 + strlen(url) + (namelen << 1), url, name, name);
    }
    return true;
}


static bool handle_directory(struct http_request *request)
{
    struct file *fp;
    char buf[SEND_BUFFER_SIZE] = {0}, pwd[BUFFER_SIZE] = {0};
    request->dir_context.actor = tracedir;

    if (request->method != HTTP_GET) {
        SEND_HTTP_MSG(request->socket, buf, "%s%s%s%s%s",
                      "HTTP/1.1 501 Not Implemented\r\n",
                      "Content-Type: text/plain\r\n", "Content-Length: 19\r\n",
                      "Connection: Close\r\n\r\n", "501 Not Implemented");
        return false;
    }

    catstr(pwd, daemon_list.dir_path, request->request_url);
    fp = filp_open(pwd, O_RDONLY, 0);


    if (IS_ERR(fp)) {
        SEND_HTTP_MSG(request->socket, buf, "%s%s%s%s%s",
                      "HTTP/1.1 404 Not Found\r\n",
                      "Content-Type: text/plain\r\n", "Content-Length: 13\r\n",
                      "Connection: Close\r\n\r\n", "404 Not Found");
        return false;
    }

    if (S_ISDIR(fp->f_inode->i_mode)) {
        SEND_HTTP_MSG(request->socket, buf, "%s%s%s", "HTTP/1.1 200 OK\r\n",
                      "Content-Type: text/html\r\n",
                      "Transfer-Encoding: chunked\r\n\r\n");
        SEND_HTTP_MSG(
            request->socket, buf, "7B\r\n%s%s%s%s", "<html><head><style>\r\n",
            "body{font-family: monospace; font-size: 15px;}\r\n",
            "td {padding: 1.5px 6px;}\r\n", "</style></head><body><table>\r\n");

        iterate_dir(fp, &request->dir_context);

        SEND_HTTP_MSG(request->socket, buf, "%s",
                      "16\r\n</table></body></html>\r\n");
        SEND_HTTP_MSG(request->socket, buf, "%s", "0\r\n\r\n");
    } else if (S_ISREG(fp->f_inode->i_mode)) {
        char *read_data = kmalloc(fp->f_inode->i_size, GFP_KERNEL);
        int ret = read_file(fp, read_data);

        SEND_HTTP_MSG(request->socket, buf, "%s%s%s%d%s", "HTTP/1.1 200 OK\r\n",
                      "Content-Type: text/plain\r\n", "Content-Length: ", ret,
                      "\r\nConnection: Close\r\n\r\n");
        http_server_send(request->socket, read_data, ret);
        kfree(read_data);
    }
    filp_close(fp, NULL);
    return true;
}

static int http_server_response(struct http_request *request, int keep_alive)
{
    // char *response;

    // pr_info("requested_url = %s\n", request->request_url);
    // if (request->method != HTTP_GET)
    //     response = keep_alive ? HTTP_RESPONSE_501_KEEPALIVE :
    //     HTTP_RESPONSE_501;
    // else
    //     response = keep_alive ? HTTP_RESPONSE_200_KEEPALIVE_DUMMY
    //                           : HTTP_RESPONSE_200_DUMMY;
    // http_server_send(request->socket, response, strlen(response));
    // return 0;
    if (handle_directory(request) > 0)
        pr_info("Something went wrong\n");
    return 0;
}

static int http_parser_callback_message_begin(http_parser *parser)
{
    struct http_request *request = parser->data;
    struct socket *socket = request->socket;
    memset(request, 0x00, sizeof(struct http_request));
    request->socket = socket;
    return 0;
}

static int http_parser_callback_request_url(http_parser *parser,
                                            const char *p,
                                            size_t len)
{
    struct http_request *request = parser->data;
    // if requst is "..", remove last character
    if (p[len - 1] == '/')
        len--;
    strncat(request->request_url, p, len);
    return 0;
}

static int http_parser_callback_header_field(http_parser *parser,
                                             const char *p,
                                             size_t len)
{
    return 0;
}

static int http_parser_callback_header_value(http_parser *parser,
                                             const char *p,
                                             size_t len)
{
    return 0;
}

static int http_parser_callback_headers_complete(http_parser *parser)
{
    struct http_request *request = parser->data;
    request->method = parser->method;
    return 0;
}

static int http_parser_callback_body(http_parser *parser,
                                     const char *p,
                                     size_t len)
{
    return 0;
}

static int http_parser_callback_message_complete(http_parser *parser)
{
    struct http_request *request = parser->data;
    http_server_response(request, http_should_keep_alive(parser));
    request->complete = 1;
    return 0;
}

static void http_server_worker(struct work_struct *work)
{
    struct http_request *worker =
        container_of(work, struct http_request, khttpd_work);
    char *buf;
    struct http_parser parser;
    struct http_parser_settings setting = {
        .on_message_begin = http_parser_callback_message_begin,
        .on_url = http_parser_callback_request_url,
        .on_header_field = http_parser_callback_header_field,
        .on_header_value = http_parser_callback_header_value,
        .on_headers_complete = http_parser_callback_headers_complete,
        .on_body = http_parser_callback_body,
        .on_message_complete = http_parser_callback_message_complete};


    allow_signal(SIGKILL);
    allow_signal(SIGTERM);

rekmalloc:
    buf = kmalloc(RECV_BUFFER_SIZE, GFP_KERNEL);
    if (!buf) {
        // TRACE(kmalloc_err);
        goto rekmalloc;
    }
    // set the initial parameter of parser
    http_parser_init(&parser, HTTP_REQUEST);
    parser.data = &worker->socket;
    // check the thread should be stop or not
    while (!daemon_list.is_stopped) {
        // receive data
        int ret = http_server_recv(worker->socket, buf, RECV_BUFFER_SIZE - 1);
        if (ret <= 0) {
            if (ret)
                // TRACE(recv_err);
                break;
        } else
            // TRACE(recvmsg);
            // parse the data received
            http_parser_execute(&parser, &setting, buf, ret);
        if (worker->complete && !http_should_keep_alive(&parser))
            break;
        memset(buf, 0, ret);
    }
    kernel_sock_shutdown(worker->socket, SHUT_RDWR);
    kfree(buf);
}


static void free_work(void)
{
    struct http_request *l, *tar;
    /* cppcheck-suppress uninitvar */

    list_for_each_entry_safe (tar, l, &daemon_list.head, node) {
        kernel_sock_shutdown(tar->socket, SHUT_RDWR);
        flush_work(&tar->khttpd_work);
        sock_release(tar->socket);
        kfree(tar);
    }
}

static struct work_struct *create_work(struct socket *sk)
{
    struct http_request *work;

    // 分配 http_request 結構大小的空間
    // GFP_KERNEL: 正常配置記憶體
    if (!(work = kmalloc(sizeof(struct http_request), GFP_KERNEL)))
        return NULL;

    work->socket = sk;

    // 初始化已經建立的 work ，並運行函式 http_server_worker
    INIT_WORK(&work->khttpd_work, http_server_worker);

    list_add(&work->node, &daemon_list.head);

    return &work->khttpd_work;
}

int http_server_daemon(void *arg)
{
    struct socket *socket;
    struct work_struct *worker;
    struct http_server_param *param = (struct http_server_param *) arg;



    allow_signal(SIGKILL);
    allow_signal(SIGTERM);

    INIT_LIST_HEAD(&daemon_list.head);


    while (!kthread_should_stop()) {
        int err = kernel_accept(param->listen_socket, &socket, 0);
        if (err < 0) {
            // check there is any signal occurred or not
            if (signal_pending(current))
                break;
            // TRACE(accept_err);
            continue;
        }
        // 利用 CMWQ 的方式建立 worker
        worker = create_work(socket);
        if (IS_ERR(worker)) {
            // TRACE(cthread_err);
            kernel_sock_shutdown(socket, SHUT_RDWR);
            sock_release(socket);
            continue;
        }

        /* start server worker */
        queue_work(khttpd_wq, worker);
    }
    daemon_list.is_stopped = true;
    free_work();
    return 0;
}
