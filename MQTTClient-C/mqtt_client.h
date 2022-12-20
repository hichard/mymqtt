/****************************************Copyright (c)****************************************************
**                             成 都 世 纪 华 宁 科 技 有 限 公 司
**                                http://www.huaning-iot.com
**                                http://hichard.taobao.com
**
**
**--------------File Info---------------------------------------------------------------------------------
** File Name:           mqtt_client.h
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
#ifndef __MQTT_CLIENT_H__
#define __MQTT_CLIENT_H__

#ifdef __cplusplus
extern "C" {
#endif

/*********************************************************************************************************
**  头文件包含
*********************************************************************************************************/
#include <stdint.h>
#include <rtthread.h>
#include "MQTTPacket.h"

#ifdef MQTT_USING_TLS
#include <tls_client.h>
#endif

/*********************************************************************************************************
**  一些配置
*********************************************************************************************************/
// 最大允许订阅的主题数量定义
#ifdef MQTT_MAX_MESSAGE_HANDLERS
#define MAX_MESSAGE_HANDLERS    MQTT_MAX_MESSAGE_HANDLERS
#else 
#define MAX_MESSAGE_HANDLERS    4
#endif
  
#ifdef MQTT_USING_TLS
#define MQTT_TLS_READ_BUFFER    4096
#endif
  
// MQTT Packet ID最大值定义，这个值符合MQTT标准规范，不能随意修改
#define MAX_PACKET_ID           65535
// TLS加密传输时使用，用于接收超时
#define MQTT_SOCKET_TIMEO       5000

/*********************************************************************************************************
**  MQTT消息链路质量值定义
*********************************************************************************************************/
enum QoS { QOS0, QOS1, QOS2, SUBFAIL=0x80 };

/*********************************************************************************************************
**  返回值，本软件包中必须为负值
*********************************************************************************************************/
enum returnCode { PAHO_BUFFER_OVERFLOW = -2, PAHO_FAILURE = -1, PAHO_SUCCESS = 0};

/*********************************************************************************************************
**  MQTT客户端配置CMD值定义，超时值都以秒为单位
*********************************************************************************************************/
enum mqttControl
{
    MQTT_CTRL_SET_CONN_TIMEO = 0,      /* set mqtt connect timeout */  
    MQTT_CTRL_SET_MSG_TIMEO,           /* set mqtt msg timeout */  
    MQTT_CTRL_SET_RECONN_INTERVAL,     /* set reconnect interval   */  
    MQTT_CTRL_SET_KEEPALIVE_INTERVAL,  /* set keepalive interval   */  
    MQTT_CTRL_SET_KEEPALIVE_COUNT      /* set keepalive count      */
}; 

/*********************************************************************************************************
**  MQTT消息结构定义
*********************************************************************************************************/
typedef struct mqtt_message
{
  enum QoS qos;
  unsigned char retained;
  unsigned char dup;
  unsigned short id;
  void *payload;
  size_t payloadlen;
} mqtt_message;

typedef struct message_data
{
  mqtt_message* message;
  MQTTString* topic_name;
} message_data;

/*********************************************************************************************************
**  定义一个消息结构，用于等待服务器应答的回应
*********************************************************************************************************/
#pragma pack(1)
typedef struct mqtt_meaasge_ack {
  uint16_t packet_id;             // mqtt package id
  uint8_t msg_type;                // mqtt 消息类型
} mqtt_message_ack;
#pragma pack()

/*********************************************************************************************************
**  MQTT客户端结构定义
*********************************************************************************************************/
typedef struct mqtt_client mqtt_client;
struct mqtt_client
{
  // 以下参数需要初始化后才能启动mqtt客户端应用
  const char *uri;
  uint8_t is_quit;           // 是否退出，必须初始化为0
  MQTTPacket_connectData condata;
  size_t buf_size, readbuf_size;
  
  // 以下参数可以先初始化在启动mqtt客户端应用，也可以启动后通过paho_mqtt_control配置
  unsigned int keepalive_interval;      // keepalive间隔，以秒为单位
  uint16_t keepalive_count;              // keepalive次数，超过该次数无应答，则关闭连接
  int connect_timeout;                  // 连接超时，以秒为单位
  int reconnect_interval;               // 重新连接间隔，以秒为单位
  int msg_timeout;                      // 消息通信超时，以秒为单位，根据网络情况，不能为0
  
  //　以下参数是应用变量，不需要初始化
  unsigned int next_packetid;
  int sock;
  unsigned char *buf, *readbuf;
  int isconnected;
  uint16_t keepalive_counter;
  uint32_t tick_ping;
  
  // 以下参数是一些回调函数，需要初始化后才能启动mqtt客户端应用
  void (*connect_callback)(mqtt_client *);
  void (*online_callback)(mqtt_client *);
  void (*offline_callback)(mqtt_client *);
  
  // 以下参数是订阅主题的回调函数，需要初始化后在启动mqtt客户端应用
  struct message_handlers
  {
    char *topicFilter;
    void (*callback)(mqtt_client *, message_data *);
    enum QoS qos;
  } message_handlers[MAX_MESSAGE_HANDLERS];      /* Message handlers are indexed by subscription topic */
  void (*default_message_handlers) (mqtt_client *, message_data *);
  
  //　以下参数是应用变量，不需要初始化
  rt_mutex_t mqtt_lock;                          /* mqtt lock */
  rt_mq_t    msg_queue;                         /* 用于处理应答包 */
#ifdef MQTT_USING_TLS
    MbedTLSSession *tls_session;                /* mbedtls session struct */
    const char *certs;                         /* mbedtls CA certs */
    uint16_t certs_len;                         /* mbedtls CA certs  length */
#endif
};

/* subscribe topic receive data callback */
typedef void (*subscribe_cb)(mqtt_client *client, message_data *data);

/*********************************************************************************************************
** 外部函数声明
*********************************************************************************************************/
extern int paho_mqtt_start(mqtt_client *client, rt_uint32_t stack_size, rt_uint8_t  priority);
extern int paho_mqtt_stop(mqtt_client *client);
extern int paho_mqtt_subscribe(mqtt_client *client, enum QoS qos, const char *topic, subscribe_cb callback);
extern int paho_mqtt_unsubscribe(mqtt_client *client, const char *topic);
extern int paho_mqtt_publish(mqtt_client *client, enum QoS qos, const char *topic, void *payload, size_t length);
extern int paho_mqtt_is_connected(mqtt_client *client);
extern int paho_mqtt_control(mqtt_client *client, int cmd, void *arg);

#ifdef __cplusplus
    }           // __cplusplus
#endif

#endif          // endif of __MQTTCLIENT_H__

/*********************************************************************************************************
** END FILE
*********************************************************************************************************/
