/****************************************Copyright (c)****************************************************
**                             成 都 世 纪 华 宁 科 技 有 限 公 司
**                                http://www.huaning-iot.com
**                                http://hichard.taobao.com
**
**
**--------------File Info---------------------------------------------------------------------------------
** File Name:           mqtt_client.c
** Last modified Date:  2019-10-25
** Last Version:        v1.0
** Description:         mqtt客户端组件实现
**
**--------------------------------------------------------------------------------------------------------
** Created By:          Renhaibo任海波
** Created date:        2019-10-25
** Version:             v1.0
** Descriptions:        The original version 初始版本
**
**--------------------------------------------------------------------------------------------------------
** Modified by:
** Modified date:
** Version:
** Description:
**
*********************************************************************************************************/
#include <string.h>
#include <stdint.h>

#include <rtthread.h>
#include <rtdevice.h>
#include <dfs_posix.h>
#include <sys/time.h>

#include <netdb.h>
#include <sys/socket.h>
#include <sys/select.h>

#include "mqtt_client.h"

/*********************************************************************************************************
**  调试配置
*********************************************************************************************************/
#define DBG_ENABLE
#define DBG_SECTION_NAME    "mqtt"

#define MQTT_DEBUG
#ifdef MQTT_DEBUG
#define DBG_LEVEL           DBG_WARNING
#else
#define DBG_LEVEL           DBG_INFO
#endif /* MQTT_DEBUG */
#define DBG_COLOR
#include <rtdbg.h>

#ifndef LOG_D
#error "Please update the 'rtdbg.h' file to GitHub latest version (https://github.com/RT-Thread/rt-thread/blob/master/include/rtdbg.h)"
#endif

/*********************************************************************************************************
**  mqtt客户端通信锁
*********************************************************************************************************/
#define mqtt_client_lock(c)          rt_mutex_take(c->mqtt_lock, RT_WAITING_FOREVER)
#define mqtt_client_unlock(c)        rt_mutex_release(c->mqtt_lock)

/*********************************************************************************************************
** Function name:       mqtt_resolve_uri
** Descriptions:        mqtt url地址解析
** input parameters:    c:    mqtt客户端结构实例，里面已经赋值了url地址     
** output parameters:   res： 解析IP地址和端口号存放
** Returned value:      0：解析成功； 其它：解析失败
**      URL example:
**      tcp://192.168.10.151:1883
**      tls://192.168.10.151:61614
**      ssl://192.168.10.151:61614
**      tcp://[fe80::20c:29ff:fe9a:a07e]:1883
**      tls://[fe80::20c:29ff:fe9a:a07e]:61614
**      ssl://[fe80::20c:29ff:fe9a:a07e]:61614
*********************************************************************************************************/
static int mqtt_resolve_uri(mqtt_client *c, struct addrinfo **res)
{
  int rc = 0;
  int uri_len = 0, host_addr_len = 0, port_len = 0;
  char *ptr;
  char port_str[6] = {0};      /* default port of mqtt(http) */
  
  const char *host_addr = 0;
  char *host_addr_new = RT_NULL;
  const char *uri = c->uri;
  uri_len = strlen(uri);
  
  /* strip protocol(tcp or ssl) */
  if (strncmp(uri, "tcp://", 6) == 0)
  {
    host_addr = uri + 6;
  }
  else if ((strncmp(uri, "ssl://", 6) == 0) || (strncmp(uri, "tls://", 6) == 0))
  {
    host_addr = uri + 6;
    
#ifndef MQTT_USING_TLS
    LOG_W("Warning: tls uri, please enable mqtt tls support!");
    rc = -1;
    goto _exit;
#endif
  }
  else
  {
    rc = -1;
    goto _exit;
  }
  
  /* ipv6 address */
  if (host_addr[0] == '[')
  {
    host_addr += 1;
    ptr = strstr(host_addr, "]");
    if (!ptr)
    {
      rc = -1;
      goto _exit;
    }
    host_addr_len = ptr - host_addr;
    if ((host_addr_len < 1) || (host_addr_len > uri_len))
    {
      rc = -1;
      goto _exit;
    }
    
    port_len = uri_len - 6 - host_addr_len - 3;
    if (port_len >= 6 || port_len < 1)
    {
      rc = -1;
      goto _exit;
    }
    
    strncpy(port_str, host_addr + host_addr_len + 2, port_len);
    port_str[port_len] = '\0';
    LOG_D("ipv6 address port: %s", port_str);
  }
  else /* ipv4 or domain. */
  {
    ptr = strstr(host_addr, ":");
    if (!ptr)
    {
      rc = -1;
      goto _exit;
    }
    host_addr_len = ptr - host_addr;
    if ((host_addr_len < 1) || (host_addr_len > uri_len))
    {
      rc = -1;
      goto _exit;
    }
    
    port_len = uri_len - 6 - host_addr_len - 1;
    if (port_len >= 6 || port_len < 1)
    {
      rc = -1;
      goto _exit;
    }
    
    strncpy(port_str, host_addr + host_addr_len + 1, port_len);
    port_str[port_len] = '\0';
    LOG_D("ipv4 address port: %s", port_str);
  }
  
  /* get host addr ok. */
  {
    /* resolve the host name. */
    struct addrinfo hint;
    int ret;
    
    host_addr_new = rt_malloc(host_addr_len + 1);
    
    if (!host_addr_new)
    {
      rc = -1;
      goto _exit;
    }
    
    memcpy(host_addr_new, host_addr, host_addr_len);
    host_addr_new[host_addr_len] = '\0';
    LOG_D("HOST = '%s'", host_addr_new);
    
#ifdef MQTT_USING_TLS
    if (c->tls_session)
    {
      c->tls_session->host = rt_strdup(host_addr_new);
      c->tls_session->port = rt_strdup(port_str);
    }
#endif
    
    memset(&hint, 0, sizeof(hint));
    
    ret = getaddrinfo(host_addr_new, port_str, &hint, res);
    if (ret != 0)
    {
      LOG_E("getaddrinfo err: %d '%s'", ret, host_addr_new);
      rc = -1;
      goto _exit;
    }
  }
  
_exit:
  if (host_addr_new != RT_NULL)
  {
    rt_free(host_addr_new);
    host_addr_new = RT_NULL;
  }
  return rc;
}

#ifdef MQTT_USING_TLS
/*********************************************************************************************************
** Function name:       mqtt_open_tls
** Descriptions:        打开tls加密传输，分配加密传输的资源
** input parameters:    c:    mqtt客户端结构实例
** output parameters:   NONE
** Returned value:      RT_EOK：打开成功； 其它：错误码
*********************************************************************************************************/
static int mqtt_open_tls(mqtt_client *c)
{
  int tls_ret = 0;
  const char *pers = "mqtt";
  
  if (!c)
    return -RT_ERROR;
  
  c->tls_session = (MbedTLSSession *)rt_malloc(sizeof(MbedTLSSession));
  if (c->tls_session == RT_NULL)
  {
    LOG_E("open tls failed, no memory for tls_session buffer malloc");
    return -RT_ENOMEM;
  }
  memset(c->tls_session, 0x0, sizeof(MbedTLSSession));
  
  c->tls_session->buffer_len = MQTT_TLS_READ_BUFFER;
  c->tls_session->buffer = rt_malloc(c->tls_session->buffer_len);
  if (c->tls_session->buffer == RT_NULL)
  {
    LOG_E("open tls failed, no memory for tls_session buffer malloc");
    rt_free(c->tls_session);
    c->tls_session = RT_NULL;
    return -RT_ENOMEM;
  }
  
  if ((tls_ret = mbedtls_client_init(c->tls_session, (void *)pers, strlen(pers))) < 0)
  {
    LOG_E("mbedtls_client_init err return : -0x%x", -tls_ret);
    return -RT_ERROR;
  }
  
  return RT_EOK;
}
#endif

/*********************************************************************************************************
** Function name:       net_connect
** Descriptions:        网络连接服务器
** input parameters:    c:    mqtt客户端结构实例
** output parameters:   NONE
** Returned value:      0：连接成功； 其它：连接失败
*********************************************************************************************************/
static int net_connect(mqtt_client *c)
{
  int rc = -1;
  struct addrinfo *addr_res = RT_NULL;
  struct timeval timeout;
  struct linger so_linger;
  
  timeout.tv_sec = MQTT_SOCKET_TIMEO / 1000;
  timeout.tv_usec = 0;
  c->sock = -1;
  c->next_packetid = 0;
  
#ifdef MQTT_USING_TLS
  if((strncmp(c->uri, "ssl://", 6) == 0) || (strncmp(c->uri, "tls://", 6) == 0))
  {
    if (mqtt_open_tls(c) < 0)
    {
      LOG_E("mqtt_open_tls err!");
      return -RT_ERROR;
    }
  }
  else
  {
    c->tls_session = RT_NULL;
  }
#endif
  
  rc = mqtt_resolve_uri(c, &addr_res);
  if (rc < 0 || addr_res == RT_NULL)
  {
    LOG_E("resolve uri err");
    goto _exit;
  }
  if (addr_res)
  {
    freeaddrinfo(addr_res);
    addr_res = RT_NULL;
  }

  
#ifdef MQTT_USING_TLS
  if (c->tls_session)
  {
    int tls_ret = 0;
    
    if ((tls_ret = mbedtls_client_context(c->tls_session, c->certs, c->certs_len)) < 0)
    {
      LOG_E("mbedtls_client_context err return : -0x%x", -tls_ret);
      return -RT_ERROR;
    }
    
    if ((tls_ret = mbedtls_client_connect(c->tls_session)) < 0)
    {
      LOG_E("mbedtls_client_connect err return : -0x%x", -tls_ret);
      rc = -RT_ERROR;
      goto _exit;
    }
    LOG_D("tls connect success...");
    
    c->sock = c->tls_session->server_fd.fd;
    
    /* set close info */
    so_linger.l_onoff = 1;
    so_linger.l_linger = 0;
    setsockopt(c->sock,SOL_SOCKET,SO_LINGER, &so_linger,sizeof(so_linger));
  
    
    /* set recv timeout option */
    setsockopt(c->sock, SOL_SOCKET, SO_RCVTIMEO, (void *) &timeout,
               sizeof(timeout));
    setsockopt(c->sock, SOL_SOCKET, SO_SNDTIMEO, (void *) &timeout,
               sizeof(timeout));
    
    rc = 0;
    goto _exit;
  }
#endif
  
  if ((c->sock = socket(addr_res->ai_family, SOCK_STREAM, 0)) == -1)
  {
    LOG_E("create socket error!");
    rc = -2;
    goto _exit;
  }

  if ((rc = connect(c->sock, addr_res->ai_addr, addr_res->ai_addrlen)) == -1)
  {
    LOG_E("connect err!");
    shutdown(c->sock, SHUT_RDWR);
    closesocket(c->sock);
    c->sock = -1;
    
    rc = -2;
    goto _exit;
  }

  /* set close info */
  so_linger.l_onoff = 1;
  so_linger.l_linger = 0;
  setsockopt(c->sock,SOL_SOCKET,SO_LINGER, &so_linger,sizeof(so_linger));
  
  /* set recv timeout option */
  setsockopt(c->sock, SOL_SOCKET, SO_RCVTIMEO, (void *) &timeout,
             sizeof(timeout));
  setsockopt(c->sock, SOL_SOCKET, SO_SNDTIMEO, (void *) &timeout,
             sizeof(timeout));
  rc = 0;
  
_exit:
  if (addr_res)
  {
    freeaddrinfo(addr_res);
    addr_res = RT_NULL;
  }
  return rc;
}

/*********************************************************************************************************
** Function name:       net_disconnect
** Descriptions:        网络关闭连接
** input parameters:    c:    mqtt客户端结构实例
** output parameters:   NONE
** Returned value:      0：关闭成功
*********************************************************************************************************/
static int net_disconnect(mqtt_client *c)
{
  mqtt_client_lock(c);
#ifdef MQTT_USING_TLS
  if (c->tls_session)
  {
    mbedtls_client_close(c->tls_session);
    c->sock = -1;
    mqtt_client_unlock(c)
    return 0;
  }
#endif
  
  if (c->sock >= 0)
  {
    shutdown(c->sock, SHUT_RDWR);
    closesocket(c->sock);
    c->sock = -1;
  }
  
  mqtt_client_unlock(c);
  return 0;
}

/*********************************************************************************************************
** Function name:       net_disconnect_exit
** Descriptions:        mqtt关闭，释放资源
** input parameters:    c:    mqtt客户端结构实例
** output parameters:   NONE
** Returned value:      0：关闭成功
*********************************************************************************************************/
static int net_disconnect_exit(mqtt_client *c)
{
  int i;
  
  net_disconnect(c);

  c->isconnected = 0;
  
  if (c->buf && c->readbuf)
  {
    rt_free(c->buf);
    rt_free(c->readbuf);
  }
  
  if (c->mqtt_lock)
  {
    rt_mutex_delete(c->mqtt_lock);
  }
  
  if (c->msg_queue)
  {
    rt_mq_delete(c->msg_queue);
  }
  
  for (i = 0; i < MAX_MESSAGE_HANDLERS; ++i)
  {
    if (c->message_handlers[i].topicFilter)
    {
      rt_free(c->message_handlers[i].topicFilter);
      c->message_handlers[i].topicFilter = RT_NULL;
      c->message_handlers[i].callback = RT_NULL;
    }
  }
  
  return 0;
}

/*********************************************************************************************************
** Function name:       send_packet
** Descriptions:        网络发送一个数据包
** input parameters:    c:    mqtt客户端结构实例
**                      buf:  发送数据缓冲区
**                      length： 发送数据长度
** output parameters:   NONE
** Returned value:      PAHO_FAILURE: 发送失败，发生了一些异常，需要关闭连接
**                      PAHO_SUCCESS： 发送成功
*********************************************************************************************************/
static int send_packet(mqtt_client *c, void *buf, int length)
{
  int total = 0;                  // how many bytes we've sent
  int bytesleft = length;         // how many we have left to send
  int rc;
  
#ifdef MQTT_USING_TLS
  if (c->tls_session) {
    while(total < length) {
      rc = mbedtls_client_write(c->tls_session, &c->buf[total], bytesleft);
      if(rc <= 0) {
        if(rc != MBEDTLS_ERR_SSL_WANT_READ && rc != MBEDTLS_ERR_SSL_WANT_WRITE) {
          break;
        }
      } else {
        total += rc;
        bytesleft -= rc;
      }
    }
    goto __send_exit;
  }
#endif
  
  while(total < length) {
    rc = send(c->sock, &c->buf[total], bytesleft, 0);
    if(rc <= 0) {
      if(!(errno == EINTR || errno == EWOULDBLOCK || errno == EAGAIN)) {
        break;
      }
    } else {
      total += rc;
      bytesleft -= rc;
    }
  }
  
#ifdef MQTT_USING_TLS
__send_exit:
#endif
  
  if(rc <= 0) {
    return PAHO_FAILURE;
  } else {
    return PAHO_SUCCESS;
  }
}

/*********************************************************************************************************
** Function name:       recv_packet
** Descriptions:        网络接收数据包
** input parameters:    c:    mqtt客户端结构实例
** output parameters:   NONE
** Returned value:      -1:     连接已断开
**                      bytes： 读到的数据长度
*********************************************************************************************************/
static int recv_packet(mqtt_client *c, unsigned char *buf,  int len, int timeout)
{
  int bytes = 0;
  int rc;
  rt_tick_t start = rt_tick_get();
  rt_tick_t end_tick = rt_tick_from_millisecond(timeout);
  
  while (bytes < len)
  {
    
#ifdef MQTT_USING_TLS
    if (c->tls_session) {
      rc = mbedtls_client_read(c->tls_session, &buf[bytes], (size_t)(len - bytes));
      if (rc <= 0){
        if(rc != MBEDTLS_ERR_SSL_WANT_READ && rc != MBEDTLS_ERR_SSL_WANT_WRITE) {
          bytes = -1;
          break;
        }
      } else {
        bytes += rc;
      }
      goto __recv_exit;
    }
#endif
    
    rc = recv(c->sock, &buf[bytes], (size_t)(len - bytes), 0);
    if (rc == -1) {
      if(!(errno == EINTR || errno == EWOULDBLOCK || errno == EAGAIN)) {
        bytes = -1;
        break;
      }
    } else if(rc == 0) {
      bytes = -1;
      break;
    } else
      bytes += rc;
    
#ifdef MQTT_USING_TLS
  __recv_exit:
#endif
    
    if(rt_tick_get() - start > end_tick) {
      break;
    }
  }
  
  return bytes;
}

/*********************************************************************************************************
** Function name:       decode_packet
** Descriptions:        读取并解析mqtt帧中的长度字段
** input parameters:    c:        mqtt客户端结构实例
**                      timeout： 读取超时时间，以毫秒为单位
** output parameters:   value： 读取长度存放地址
** Returned value:      读取次数
*********************************************************************************************************/
static int decode_packet(mqtt_client *c, int *value, int timeout)
{
  unsigned char i;
  int multiplier = 1;
  int len = 0;
  const int MAX_NO_OF_REMAINING_LENGTH_BYTES = 4;
  
  *value = 0;
  do
  {
    int rc = MQTTPACKET_READ_ERROR;
    
    if (++len > MAX_NO_OF_REMAINING_LENGTH_BYTES)
    {
      rc = MQTTPACKET_READ_ERROR; /* bad data */
      goto exit;
    }
    rc = recv_packet(c, &i, 1, timeout);
    if (rc != 1)
      goto exit;
    *value += (i & 127) * multiplier;
    multiplier *= 128;
  }
  while ((i & 128) != 0);
exit:
  return len;
}

/*********************************************************************************************************
** Function name:       mqttpacket_readpacket
** Descriptions:        读取一个mqtt数据包
** input parameters:    c:        mqtt客户端结构实例
** output parameters:   NULL
** Returned value:      数据包类型
*********************************************************************************************************/
static int mqttpacket_readpacket(mqtt_client *c)
{
  int rc = PAHO_FAILURE;
  MQTTHeader header = {0};
  int len = 0;
  int rem_len = 0;
  
  mqtt_client_lock(c);
  /* 1. read the header byte.  This has the packet type in it */
  if (recv_packet(c, c->readbuf, 1, 0) != 1)
    goto __read_exit;
  
  len = 1;
  /* 2. read the remaining length.  This is variable in itself */
  decode_packet(c, &rem_len, 50);
  len += MQTTPacket_encode(c->readbuf + 1, rem_len); /* put the original remaining length back into the buffer */
  if (rem_len > (c->readbuf_size - len))
    goto __read_exit;
  
  /* 3. read the rest of the buffer using a callback to supply the rest of the data */
  if (rem_len > 0 && (recv_packet(c, c->readbuf + len, rem_len, 300) != rem_len))
    goto __read_exit;
  
  header.byte = c->readbuf[0];
  rc = header.bits.type;
  c->tick_ping = rt_tick_get();
  c->keepalive_counter = 0;
  
__read_exit:
  mqtt_client_unlock(c);
  return rc;
}

/*********************************************************************************************************
** Function name:       get_next_packetId
** Descriptions:        获取下一个有效的数据包ID
** input parameters:    c:        mqtt客户端结构实例
** output parameters:   NULL
** Returned value:      获取到的数据包ID
*********************************************************************************************************/
static int get_next_packetId(mqtt_client *c)
{
  return c->next_packetid = (c->next_packetid == MAX_PACKET_ID) ? 1 : c->next_packetid + 1;
}

/*********************************************************************************************************
** Function name:       mqtt_connect
** Descriptions:        连接MQTT服务器
** input parameters:    c:        mqtt客户端结构实例
** output parameters:   NULL
** Returned value:      连接结果。-1：已经连接或连接失败；0：连接成功
*********************************************************************************************************/
static int mqtt_connect(mqtt_client *c)
{
  int rc = -1, len;
  MQTTPacket_connectData *options = &c->condata;
  
  if (c->isconnected) /* don't send connect packet again if we are already connected */
    goto __connect_exit;
  
  c->keepalive_interval = options->keepAliveInterval;
  
  mqtt_client_lock(c);
  if ((len = MQTTSerialize_connect(c->buf, c->buf_size, options)) <= 0)
    goto __connect_exit;
  
  if ((rc = send_packet(c, c->buf, len)) != PAHO_SUCCESS)  // send the connect packet
    goto __connect_exit; // there was a problem
  
  {
    int res;
    fd_set readset;
    struct timeval timeout;
    
    timeout.tv_sec = c->connect_timeout ? c->connect_timeout : 5;
    timeout.tv_usec = 0;
    
    FD_ZERO(&readset);
    FD_SET(c->sock, &readset);
    
    res = select(c->sock + 1, &readset, RT_NULL, RT_NULL, &timeout);
    
    if (res <= 0)
    {
      LOG_E("%s wait resp fail, res:%d errno:%d", __FUNCTION__, res, errno);
      rc = -1;
      goto __connect_exit;
    }
  }
  
  rc = mqttpacket_readpacket(c);
  if (rc < 0)
  {
    LOG_E("%s MQTTPacket_readPacket fail", __FUNCTION__);
    goto __connect_exit;
  }
  
  if (rc == CONNACK)
  {
    unsigned char sessionPresent, connack_rc;
    
    if (MQTTDeserialize_connack(&sessionPresent, &connack_rc, c->readbuf, c->readbuf_size) == 1)
    {
      rc = connack_rc;
    }
    else
    {
      rc = -1;
    }
  }
  else
    rc = -1;
  
__connect_exit:
  mqtt_client_unlock(c);
  if (rc == 0)
    c->isconnected = 1;
  
  return rc;
}

/*********************************************************************************************************
** Function name:       mqtt_disconnect
** Descriptions:        断开连接MQTT服务器
** input parameters:    c:        mqtt客户端结构实例
** output parameters:   NULL
** Returned value:      获取到的数据包ID
*********************************************************************************************************/
static int mqtt_disconnect(mqtt_client *c)
{
  int rc = PAHO_FAILURE;
  int len = 0;
  
  mqtt_client_lock(c);
  len = MQTTSerialize_disconnect(c->buf, c->buf_size);
  if (len > 0)
    rc = send_packet(c, c->buf, len);            // send the disconnect packet
  
  c->isconnected = 0;
  
  mqtt_client_unlock(c);
  return rc;
}

/*********************************************************************************************************
** Function name:       mqtt_subscribe
** Descriptions:        MQTT主题订阅
** input parameters:    c:        mqtt客户端结构实例
**                      topicFilter： 订阅的主题
**                      qos：     订阅主题的链路质量
** output parameters:   NULL
** Returned value:      订阅结果。0:订阅成功
*********************************************************************************************************/
static int mqtt_subscribe(mqtt_client *c, const char *topicFilter, enum QoS qos)
{
  int rc = PAHO_FAILURE;
  int len = 0;
  int qos_sub = qos;
  MQTTString topic = MQTTString_initializer;
  topic.cstring = (char *)topicFilter;
  
  if (!c->isconnected)
    goto _exit;
  
  mqtt_client_lock(c);
  len = MQTTSerialize_subscribe(c->buf, c->buf_size, 0, get_next_packetId(c), 1, &topic, &qos_sub);
  if (len <= 0)
    goto _exit;
  if ((rc = send_packet(c, c->buf, len)) != PAHO_SUCCESS) // send the subscribe packet
    goto _exit;             // there was a problem
  
  {
    int res;
    fd_set readset;
    struct timeval timeout;
    
    timeout.tv_sec = c->msg_timeout;
    timeout.tv_usec = 0;
    
    FD_ZERO(&readset);
    FD_SET(c->sock, &readset);
    
    res = select(c->sock + 1, &readset, RT_NULL, RT_NULL, &timeout);
    
    if (res <= 0)
    {
      LOG_E("%s wait resp fail, res:%d errno:%d", __FUNCTION__, res, errno);
      rc = -1;
      goto _exit;
    }
  }
  
  rc = mqttpacket_readpacket(c);
  if (rc < 0)
  {
    LOG_E("mqtt_subscribe MQTTPacket_readPacket mqtt_connect fail");
    goto _exit;
  }
  
  if (rc == SUBACK)       // wait for suback
  {
    int count = 0, grantedQoS = -1;
    unsigned short mypacketid;
    
    if (MQTTDeserialize_suback(&mypacketid, 1, &count, &grantedQoS, c->readbuf, c->readbuf_size) == 1)
      rc = grantedQoS; // 0, 1, 2 or 0x80
    
    if (rc != 0x80)
    {
      rc = 0;
    }
  }
  else
    rc = PAHO_FAILURE;
  
_exit:
  mqtt_client_unlock(c);
  return rc;
}

/*********************************************************************************************************
** Function name:       new_message_data
** Descriptions:        赋值一个消息
** input parameters:    md:          待赋值的消息
**                      aTopicName： 消息主题
**                      aMessage：   消息内容
** output parameters:   NULL
** Returned value:      NULL
*********************************************************************************************************/
static void new_message_data(message_data *md, MQTTString *aTopicName, mqtt_message *aMessage)
{
  md->topic_name = aTopicName;
  md->message = aMessage;
}

/*********************************************************************************************************
** Function name:       is_topic_matched
** Descriptions:        校验主题是否匹配
** input parameters:    topicFilter:  匹配目的主题
**                      topic_name：   匹配源主题
** output parameters:   NULL
** Returned value:      匹配结果。0：匹配失败；1：匹配成功
**   通配符说明：
**   #can only be at end
**   + and # can only be next to separator
*********************************************************************************************************/
static char is_topic_matched(char *topicFilter, MQTTString *topic_name)
{
  char *curf = topicFilter;
  char *curn = topic_name->lenstring.data;
  char *curn_end = curn + topic_name->lenstring.len;
  
  while (*curf && curn < curn_end)
  {
    if (*curn == '/' && *curf != '/')
      break;
    if (*curf != '+' && *curf != '#' && *curf != *curn)
      break;
    if (*curf == '+')
    {
      // skip until we meet the next separator, or end of string
      char *nextpos = curn + 1;
      while (nextpos < curn_end && *nextpos != '/')
        nextpos = ++curn + 1;
    }
    else if (*curf == '#')
      curn = curn_end - 1;    // skip until end of string
    curf++;
    curn++;
  };
  
  return (curn == curn_end) && (*curf == '\0');
}

/*********************************************************************************************************
** Function name:       deliver_message
** Descriptions:        处理MQTT消息
** input parameters:    topicFilter:  匹配目的主题
**                      topic_name：   匹配源主题
** output parameters:   NULL
** Returned value:      处理结果
*********************************************************************************************************/
static int deliver_message(mqtt_client *c, MQTTString *topic_name, mqtt_message *message)
{
  int i;
  int rc = PAHO_FAILURE;
  
  // we have to find the right message handler - indexed by topic
  for (i = 0; i < MAX_MESSAGE_HANDLERS; ++i)
  {
    if (c->message_handlers[i].topicFilter != 0 && (MQTTPacket_equals(topic_name, (char *)c->message_handlers[i].topicFilter) ||
                                                    is_topic_matched((char *)c->message_handlers[i].topicFilter, topic_name)))
    {
      if (c->message_handlers[i].callback != NULL)
      {
        message_data md;
        new_message_data(&md, topic_name, message);
        c->message_handlers[i].callback(c, &md);
        rc = PAHO_SUCCESS;
      }
    }
  }
  
  if (rc == PAHO_FAILURE && c->default_message_handlers != NULL)
  {
    message_data md;
    new_message_data(&md, topic_name, message);
    c->default_message_handlers(c, &md);
    rc = PAHO_SUCCESS;
  }
  
  return rc;
}

/*********************************************************************************************************
** Function name:       mqtt_cycle
** Descriptions:        处理MQTT消息
** input parameters:    c:        mqtt客户端结构实例
** output parameters:   NULL
** Returned value:      处理结果
*********************************************************************************************************/
static int mqtt_cycle(mqtt_client *c)
{
  int len = 0, rc = PAHO_SUCCESS;
  // read the socket, see what work is due
  int packet_type = mqttpacket_readpacket(c);
  
  if (packet_type == -1)
  {
    rc = PAHO_FAILURE;
    goto __cycle_exit;
  }
  
  switch (packet_type)
  {
  case CONNACK:
    break;
  case PUBACK:
    {
      uint16_t mypacketid;
      uint8_t dup, type;
      if (MQTTDeserialize_ack(&type, &dup, &mypacketid, c->readbuf, c->readbuf_size) == 1) {
        mqtt_message_ack msg;
        msg.packet_id = mypacketid;
        msg.msg_type = PUBACK;
        rt_mq_send(c->msg_queue, &msg, sizeof(mqtt_message_ack));
      }
    }
    break;
  case PUBCOMP:
    {
      uint16_t mypacketid;
      uint8_t dup, type;
      if (MQTTDeserialize_ack(&type, &dup, &mypacketid, c->readbuf, c->readbuf_size) == 1) {
        mqtt_message_ack msg;
        msg.packet_id = mypacketid;
        msg.msg_type = PUBCOMP;
        rt_mq_send(c->msg_queue, &msg, sizeof(mqtt_message_ack));
      }
    }
    break;
  case SUBACK:
    {
      int count = 0, grantedQoS = -1;
      unsigned short mypacketid;
      
      if (MQTTDeserialize_suback(&mypacketid, 1, &count, &grantedQoS, c->readbuf, c->readbuf_size) == 1)
        rc = grantedQoS; // 0, 1, 2 or 0x80
      
      if (rc != 0x80) {
        mqtt_message_ack msg;
        msg.packet_id = mypacketid;
        msg.msg_type = SUBACK;
        rc = 0;
        rt_mq_send(c->msg_queue, &msg, sizeof(mqtt_message_ack));
      }
    } 
    break;
  case UNSUBACK:
    {
      unsigned short mypacketid;
      
      if (MQTTDeserialize_unsuback(&mypacketid, c->readbuf, c->readbuf_size) == 1) {
        mqtt_message_ack msg;
        msg.packet_id = mypacketid;
        msg.msg_type = UNSUBACK;
        rc = PAHO_SUCCESS;
        rt_mq_send(c->msg_queue, &msg, sizeof(mqtt_message_ack));
      } else
        rc =  PAHO_FAILURE;
    }
    break;
  case PUBLISH:
    {
      MQTTString topic_name;
      mqtt_message msg;
      int intQoS;
      if (MQTTDeserialize_publish(&msg.dup, &intQoS, &msg.retained, &msg.id, &topic_name,
                                  (unsigned char **)&msg.payload, (int *)&msg.payloadlen, c->readbuf, c->readbuf_size) != 1)
        goto __cycle_exit;
      msg.qos = (enum QoS)intQoS;
      deliver_message(c, &topic_name, &msg);
      if (msg.qos != QOS0)
      {
        mqtt_client_lock(c);
        if (msg.qos == QOS1)
          len = MQTTSerialize_ack(c->buf, c->buf_size, PUBACK, 0, msg.id);
        else if (msg.qos == QOS2)
          len = MQTTSerialize_ack(c->buf, c->buf_size, PUBREC, 0, msg.id);
        if (len <= 0)
          rc = PAHO_FAILURE;
        else
          rc = send_packet(c, c->buf, len);
        mqtt_client_unlock(c);
        
        if (rc == PAHO_FAILURE)
          goto __cycle_exit; // there was a problem
      }
    }
    break;
  case PUBREC:
  case PUBREL:
    {
      unsigned short mypacketid;
      unsigned char dup, type;
      
      mqtt_client_lock(c);
      if (MQTTDeserialize_ack(&type, &dup, &mypacketid, c->readbuf, c->readbuf_size) != 1)
        rc = PAHO_FAILURE;
      else if ((len = MQTTSerialize_ack(c->buf, c->buf_size,
                                        (packet_type == PUBREC) ? PUBREL : PUBCOMP, 0, mypacketid)) <= 0)
        rc = PAHO_FAILURE;
      else if ((rc = send_packet(c, c->buf, len)) != PAHO_SUCCESS) // send the PUBREL packet
        rc = PAHO_FAILURE; // there was a problem
      mqtt_client_unlock(c);
      
      if (rc == PAHO_FAILURE)
        goto __cycle_exit; // there was a problem
    }
    break;
  case PINGRESP:
    break;
  }
  
__cycle_exit:
  return rc;
}

/*********************************************************************************************************
** Function name:       paho_mqtt_thread
** Descriptions:        mqtt处理核心线程
** input parameters:    param: 线程传入参数
** output parameters:   NULL
** Returned value:      NULL
*********************************************************************************************************/
static void paho_mqtt_thread(void *param)
{
  mqtt_client *c = (mqtt_client *)param;
  int i, rc, len;
  int rc_t = 0;
  
  // 配置参数检查
  if(c->keepalive_interval == 0) {
    c->keepalive_interval = 60;
  }
  if(c->keepalive_count == 0) { 
    c->keepalive_count = 3;
  }
  if(c->connect_timeout == 0) {
    c->connect_timeout = 5;
  }
  if(c->reconnect_interval == 0) {
    c->reconnect_interval = 5;
  }
  if(c->msg_timeout == 0) {
    c->msg_timeout = 5;
  }
  
  c->is_quit = 0;
__mqtt_start:
  if (c->connect_callback)
  {
    c->connect_callback(c);
  }
  
  rc = net_connect(c);
  if (rc != 0)
  {
    LOG_E("Net connect error(%d).", rc);
    goto __mqtt_restart;
  }
  
  rc = mqtt_connect(c);
  if (rc != 0)
  {
    LOG_E("MQTT connect error(%d): %s.", rc, MQTTSerialize_connack_string(rc));
    goto __mqtt_restart;
  }
  
  LOG_I("MQTT server connect success.");
  
  for (i = 0; i < MAX_MESSAGE_HANDLERS; i++)
  {
    const char *topic = c->message_handlers[i].topicFilter;
    enum QoS qos = c->message_handlers[i].qos;
    
    if (topic == RT_NULL)
      continue;
    
    rc = mqtt_subscribe(c, topic, qos);
    LOG_I("Subscribe #%d %s %s!", i, topic, (rc < 0) || (rc == 0x80) ? ("fail") : ("OK"));
    
    if (rc != 0)
    {
      if (rc == 0x80)
      {
        LOG_E("QoS(%d) config err!", qos);
      }
      goto __mqtt_disconnect;
    }
  }
  
  if (c->online_callback)
  {
    c->online_callback(c);
  }
  
  c->tick_ping = rt_tick_get();
  c->keepalive_counter = 0;
  while (1)
  {
    int res;
    rt_tick_t tick_now;
    rt_tick_t time_diff;
    fd_set readset;
    struct timeval timeout;
    
    tick_now = rt_tick_get();
    time_diff = ((tick_now - c->tick_ping) / RT_TICK_PER_SECOND);
    if(time_diff >= c->keepalive_interval) {
      mqtt_client_lock(c);
      len = MQTTSerialize_pingreq(c->buf, c->buf_size);
      rc = send_packet(c, c->buf, len);
      mqtt_client_unlock(c);
      if (rc != 0)
      {
        LOG_E("[%d] send ping rc: %d ", rt_tick_get(), rc);
        goto __mqtt_disconnect;
      }
      timeout.tv_sec = 10;
      c->tick_ping = rt_tick_get();
      c->keepalive_counter++;
      if(c->keepalive_counter >= c->keepalive_count) {
        LOG_E("[%d] can't recv Ping Response");
        goto __mqtt_disconnect;
      }
    } else {
      timeout.tv_sec = c->keepalive_interval - time_diff;
      if(timeout.tv_sec == 0) {
        timeout.tv_sec = 1;
      }
    }
    timeout.tv_usec = 0;
    
    FD_ZERO(&readset);
    FD_SET(c->sock, &readset);
    /* int select(maxfdp1, readset, writeset, exceptset, timeout); */
    res = select(c->sock+ 1, &readset, RT_NULL, RT_NULL, &timeout);
    if (res < 0) {
      LOG_E("select res: %d", res);
      goto __mqtt_disconnect;
    }
    
    // 如果有接收到数据，则处理接收数据
    if (FD_ISSET(c->sock, &readset)) {
      rc_t = mqtt_cycle(c);
      if (rc_t < 0)    goto __mqtt_disconnect;
      
    }
    if(c->is_quit) {
      goto __mqtt_disconnect_exit;
    }
  } /* while (1) */
  
__mqtt_disconnect:
  mqtt_disconnect(c);
__mqtt_restart:
  if (c->offline_callback)
  {
    c->offline_callback(c);
  }
  
  net_disconnect(c);
  rt_thread_delay(c->reconnect_interval > 0 ? 
                  (c->reconnect_interval *  RT_TICK_PER_SECOND) : (RT_TICK_PER_SECOND * 5));
  LOG_D("restart!");
  goto __mqtt_start;
  
__mqtt_disconnect_exit:
  mqtt_disconnect(c);
  net_disconnect_exit(c);
  
  return;
}

/*********************************************************************************************************
** Function name:       paho_mqtt_start
** Descriptions:        初始化mqtt
** input parameters:    c:           mqtt客户端结构实例
**                      stack_size： mqtt核心线程栈大小
**                      priority：   mqtt核心线程优先级
** output parameters:   NULL
** Returned value:      初始化结果。PAHO_SUCCESS：成功； 其它：失败
*********************************************************************************************************/
int paho_mqtt_start(mqtt_client *client, rt_uint32_t stack_size, rt_uint8_t  priority)
{
  static uint8_t counts = 0;
  rt_thread_t tid;
  char lock_name[RT_NAME_MAX], msg_name[RT_NAME_MAX], thread_name[RT_NAME_MAX];
  
  /* create mqtt mutex */
  rt_memset(lock_name, 0x00, sizeof(lock_name));
  rt_snprintf(lock_name, RT_NAME_MAX, "mqttl%d", counts);
  client->mqtt_lock = rt_mutex_create(lock_name, RT_IPC_FLAG_PRIO);
  if (client->mqtt_lock == RT_NULL) {
    LOG_E("Create mqtt mutex error.");
    return PAHO_FAILURE;
  }
  
  /* create mqtt msg pool */
  rt_memset(msg_name, 0x00, sizeof(msg_name));
  rt_snprintf(msg_name, RT_NAME_MAX, "mqttq%d", counts);
  client->msg_queue = rt_mq_create(msg_name, sizeof(mqtt_message_ack), 8, RT_IPC_FLAG_FIFO);
  if (client->msg_queue == RT_NULL) {
    LOG_E("Create mqtt msg pool error.");
    return PAHO_FAILURE;
  }
  
  /* create mqtt thread */
  rt_memset(thread_name, 0x00, sizeof(thread_name));
  rt_snprintf(thread_name, RT_NAME_MAX, "mqttt%d", counts++);
  tid = rt_thread_create(thread_name, paho_mqtt_thread, (void *) client,
                         stack_size, priority, 10);   
  if (tid) {
    rt_thread_startup(tid);
  }
  
  return PAHO_SUCCESS;
}

/*********************************************************************************************************
** Function name:       paho_mqtt_stop
** Descriptions:        终止指定的mqtt应用
** input parameters:    c:           mqtt客户端结构实例
** output parameters:   NULL
** Returned value:      PAHO_SUCCESS：成功； 其它：失败
*********************************************************************************************************/
int paho_mqtt_stop(mqtt_client *client)
{
  client->is_quit = 1;
  return PAHO_SUCCESS;
}

/*********************************************************************************************************
** Function name:       paho_mqtt_subscribe
** Descriptions:        mqtt消息订阅
** input parameters:    client:      mqtt客户端结构实例
**                      qos：        链路质量
**                      topic:       订阅主题
**                      callback:    匹配该主题的回调函数
** output parameters:   NULL
** Returned value:      PAHO_SUCCESS：成功； 其它：失败
*********************************************************************************************************/
int paho_mqtt_subscribe(mqtt_client *client, enum QoS qos, const char *topic, subscribe_cb callback)
{
  int i, length, rc = PAHO_SUCCESS;
  int qos_sub = qos;
  MQTTString topicFilters = MQTTString_initializer;
  topicFilters.cstring = (char *)topic;
  mqtt_message_ack msg;
  
  if((client == NULL) || (topic == NULL)) {
    return PAHO_FAILURE;
  }
  
  for (i = 0; i < MAX_MESSAGE_HANDLERS ; ++i)
  {
    if (client->message_handlers[i].topicFilter && 
        rt_strncmp(client->message_handlers[i].topicFilter, topic, rt_strlen(topic)) == 0)
    {
      LOG_D("MQTT client topic(%s) is already subscribed.", topic);
      return PAHO_SUCCESS;
    }
  }
  
  for (i = 0; i < MAX_MESSAGE_HANDLERS; ++i)
  {
    if (client->message_handlers[i].topicFilter)
    {
      continue;
    }
    
    mqtt_client_lock(client);
    length = MQTTSerialize_subscribe(client->buf, client->buf_size, 0, get_next_packetId(client), 1, &topicFilters, &qos_sub);
    if (length <= 0)
    {
      LOG_E("Subscribe #%d %s failed!", i, topic);
      mqtt_client_unlock(client);
      rc = PAHO_FAILURE;
      goto __subscribe_exit;
    }
    
    rt_mq_control(client->msg_queue, RT_IPC_CMD_RESET, RT_NULL);
    rc = send_packet(client, client->buf, length);
    mqtt_client_unlock(client);
    if (rc != PAHO_SUCCESS) 
    {
      LOG_E("Subscribe #%d %s failed!", i, topic);
      rc = PAHO_FAILURE;
      goto __subscribe_exit;
    }
    if(rt_mq_recv(client->msg_queue, &msg, sizeof(mqtt_message_ack), 
                  rt_tick_from_millisecond(client->msg_timeout * 1000)) == RT_EOK) {
      if(msg.msg_type == SUBACK) {
        client->message_handlers[i].qos = qos;
        client->message_handlers[i].topicFilter = rt_strdup((char *)topic);
        if (callback)
        {
          client->message_handlers[i].callback = callback;
        }
        
        LOG_I("Subscribe #%d %s OK!", i, topic);
      } else {
        LOG_E("Subscribe #%d %s suback error!", i, topic);
        rc = PAHO_FAILURE;
      }
    } else {
      LOG_E("Subscribe #%d %s timeout!", i, topic);
      rc = PAHO_FAILURE;
    }
    goto __subscribe_exit;
  }
  
  /* check subscribe numble support */
  if (i >= MAX_MESSAGE_HANDLERS) {
    LOG_E("Subscribe MAX_MESSAGE_HANDLERS size(%d) is not enough!", MAX_MESSAGE_HANDLERS);
    rc = PAHO_FAILURE;
  }
  
__subscribe_exit:
  return rc;
}

/*********************************************************************************************************
** Function name:       paho_mqtt_unsubscribe
** Descriptions:        取消mqtt消息订阅
** input parameters:    client:      mqtt客户端结构实例
**                      topic:       订阅主题
** output parameters:   NULL
** Returned value:      PAHO_SUCCESS：成功； 其它：失败
*********************************************************************************************************/
int paho_mqtt_unsubscribe(mqtt_client *client, const char *topic)
{
  int i, length, rc = PAHO_SUCCESS;
  MQTTString topicFilter = MQTTString_initializer;
  topicFilter.cstring = (char *)topic;
  mqtt_message_ack msg;
  
  if((client == NULL) || (topic == NULL)) {
    return PAHO_FAILURE;
  }
  
  for (i = 0; i < MAX_MESSAGE_HANDLERS; ++i)
  {
    if (client->message_handlers[i].topicFilter == RT_NULL || 
        rt_strncmp(client->message_handlers[i].topicFilter, topic, rt_strlen(topic)) != 0)
    {
      continue;
    }
    
    mqtt_client_lock(client);
    length = MQTTSerialize_unsubscribe(client->buf, client->buf_size, 0, get_next_packetId(client), 1, &topicFilter);
    if (length <= 0)
    {
      LOG_E("Unubscribe #%d %s failed!", i, topic);
      mqtt_client_unlock(client);
      rc = PAHO_FAILURE;
      goto __unsubscribe_exit;
    }
    
    rt_mq_control(client->msg_queue, RT_IPC_CMD_RESET, RT_NULL);
    rc = send_packet(client, client->buf, length);
    mqtt_client_unlock(client);
    if (rc != PAHO_SUCCESS)
    {
      LOG_E("Unubscribe #%d %s failed!", i, topic);
      rc = PAHO_FAILURE;
      goto __unsubscribe_exit;
    }
    
    if(rt_mq_recv(client->msg_queue, &msg, sizeof(mqtt_message_ack), 
                  rt_tick_from_millisecond(client->msg_timeout * 1000)) == RT_EOK) {
      if(msg.msg_type == UNSUBACK) {
        /* clear message handler */
        if (client->message_handlers[i].topicFilter)
        {
          rt_free(client->message_handlers[i].topicFilter);
          client->message_handlers[i].topicFilter = RT_NULL;
        }
        client->message_handlers[i].callback = RT_NULL; 
        
        LOG_I("Unsubscribe #%d %s OK!", i, topic);
      } else {
        rc = PAHO_FAILURE;
        LOG_E("Unsubscribe #%d %s unsuback error!", i, topic);
      }
    } else {
      rc = PAHO_FAILURE;
      LOG_E("Unsubscribe #%d %s timeout!", i, topic);
    }
    
    goto __unsubscribe_exit;
  }
  
  /* check subscribe topic */
  if (i >= MAX_MESSAGE_HANDLERS)
  {
    LOG_E("Unsubscribe topic(%s) is not exist!", topic);
    rc = PAHO_FAILURE;
  }
  
__unsubscribe_exit:
  return rc;
}

/*********************************************************************************************************
** Function name:       paho_mqtt_publish
** Descriptions:        发布mqtt消息
** input parameters:    client:      mqtt客户端结构实例
**                      qos：        发布消息的链路质量
**                      topic:       发布主题
**                      payload：    发送的数据
**                      length：     数据长度
** output parameters:   NULL
** Returned value:      PAHO_SUCCESS：成功； 其它：失败
*********************************************************************************************************/
int paho_mqtt_publish(mqtt_client *client, enum QoS qos, const char *topic, void *payload, size_t length)
{
  uint16_t message_id;
  int rc = PAHO_FAILURE;
  int len;
  mqtt_message_ack msg;
  MQTTString mqtt_topic = MQTTString_initializer;
  
  if((client == NULL) || (topic == NULL) || (length == 0)) {
    return PAHO_FAILURE;
  }
  
  if (!client->isconnected)
    goto __publish_exit;
  
  mqtt_topic.cstring = (char *)topic;
  
  if (qos == QOS1 || qos == QOS2)
    message_id = get_next_packetId(client);
  else
    message_id = 0;
  
  mqtt_client_lock(client);
  len = MQTTSerialize_publish(client->buf, client->buf_size, 0, qos, 0, message_id,
                              mqtt_topic, payload, length);
  if (len <= 0) {
    mqtt_client_unlock(client);
    goto __publish_exit;
  }
  
  if (qos != QOS0) {
    rt_mq_control(client->msg_queue, RT_IPC_CMD_RESET, RT_NULL);
  }
  if ((rc = send_packet(client, client->buf, len)) != PAHO_SUCCESS) { // send the subscribe packet
    mqtt_client_unlock(client);
    goto __publish_exit; // there was a problem
  }
  mqtt_client_unlock(client);
  
  if (qos != QOS0) {
    if(rt_mq_recv(client->msg_queue, &msg, sizeof(mqtt_message_ack), 
                  rt_tick_from_millisecond(client->msg_timeout * 1000)) == RT_EOK) {
                    if((qos == QOS1) && (msg.msg_type == PUBACK)) {
                      rc = PAHO_SUCCESS;
                    } else if((qos == QOS2) && (msg.msg_type == PUBCOMP)) {
                      rc = PAHO_SUCCESS;
                    }
                  }
  } else {
    rc = PAHO_SUCCESS;
  }
__publish_exit:
  return rc;
}

/*********************************************************************************************************
** Function name:       paho_mqtt_is_connected
** Descriptions:        判断连接mqtt服务器是否成功
** input parameters:    client:      mqtt客户端结构实例
** output parameters:   NULL
** Returned value:      1: 连接成功；0：未连接
*********************************************************************************************************/
int paho_mqtt_is_connected(mqtt_client *client)
{
  return client->isconnected;
}

/*********************************************************************************************************
** Function name:       paho_mqtt_control
** Descriptions:        mqtt客户端配置
** input parameters:    c:        mqtt客户端结构实例
**                      cmd:      配置命令
**                      arg：     配置的值指针
** output parameters:   NULL
** Returned value:      配置结果。PAHO_SUCCESS：成功；其它：失败
*********************************************************************************************************/
int paho_mqtt_control(mqtt_client *client, int cmd, void *arg)
{
  if((client == NULL) || (arg == NULL)) {
    return PAHO_FAILURE;
  }
  
  switch (cmd)
  {
  case MQTT_CTRL_SET_CONN_TIMEO:
    client->connect_timeout = *(int *)arg;
    break;
    
  case MQTT_CTRL_SET_MSG_TIMEO:
    client->msg_timeout = *(int *)arg;
    break;
    
  case MQTT_CTRL_SET_RECONN_INTERVAL:
    client->reconnect_interval = *(int *)arg;
    break;
    
  case MQTT_CTRL_SET_KEEPALIVE_INTERVAL:
    client->keepalive_interval = *(unsigned int *)arg;
    break;
    
  case MQTT_CTRL_SET_KEEPALIVE_COUNT:
    client->keepalive_count = *(uint16_t *)arg;
    break;
    
  default:
    LOG_E("Input control commoand(%d) error.", cmd);
    break;
  }
  
  return PAHO_SUCCESS;
}
/*********************************************************************************************************
** END FILE
*********************************************************************************************************/

