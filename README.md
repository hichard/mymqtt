# my-mqtt
## 1、介绍
- [Paho MQTT](http://www.eclipse.org/paho/downloads.php) 是 Eclipse 实现的基于 MQTT 协议的客户端,
  本软件包是在 Eclipse [paho-mqtt](https://github.com/eclipse/paho.mqtt.embedded-c) 源码包的基础上设计的一套 MQTT 客户端程序。

- 原本rt-thread的packages中已经有了paho-mqtt软件包，但是使用中发现不少问题。首先，占用内存大、发送一次数据来回拷贝的次数多，
  其次，使用pipe通信，pipe转发mqtt订阅数据包的流程是存在问题；最后，代码结构混乱，函数及变量命令有win风格、也有linux风格。

- 鉴于原有的paho-mqtt软件包存在这样或那样的问题，于是本人重写的该软件包，命名为my-mqtt。该软件包也是基于Eclispe的Paho MQTT来
  实现的，参考了很多其它厂家的mqtt协议栈实现，力求这是最简洁，最稳定的实现，以达到商业应用的目的。

- my-mqtt实现了可商用的mqtt协议栈，它支持mqtt协议定义的Qos0、Qos1、Qos2所有协议标准等级的订阅，但是由于为了简单、可靠，处理机制
上较为简单。比如，发布一次主题，如果是Qos1或者Qos2，要等待ACK，这会影响发布主题的速率。但是如果要高效率就要像TCP那样，建立滑动
窗口的机制，这又太为复杂了。事实上目前，商用的mqtt协议栈，笔者研究了很多家的，基本都是这样简单粗暴的处理。如果用户，有更为高效的实现
方式，欢迎PR。我们目的都是为rt-thread提供一个稳定可靠，能够商用的mqtt客户端软件包。
  
- my-mqtt目录组装和之前的paho-mqtt软件包相似，代码组织和使用方式及调用函数都是相同的。本人直接拷贝了以前paho-mqtt软件包的文档。使用方式 
  都可以参考之前的软件包中的文档。
  
- 该软件包命名为my-mqtt，只是为了和之前的paho-mqtt软件包区分，这是一个全新的软件包。但是，对外基本api和paho-mqtt保持兼容，并且还扩展提供了
  一些api，以满足商业应用的需求。使用paho-mqtt的用户可以无缝切换到my-mqtt软件包。

- `my-mqtt` 软件包功能特点以及 MQTT  协议介绍请参考 [软件包详细介绍](docs/introduction.md)。

### 1.1 目录结构

`my-mqtt` 软件包目录结构如下所示：

``` 
my-mqtt
├───docs 
│   └───figures                     // 文档使用图片
│   │   api.md                      // API 使用说明
│   │   introduction.md             // 介绍文档
│   │   principle.md                // 实现原理
│   │   README.md                   // 文档结构说明  
│   │   samples.md                  // 软件包示例
│   │   user-guide.md               // 使用说明
│   └───version.md                  // 版本
├───MQTTClient-C                    // 移植实现文件
├───MQTTPacket                      // 源文件
├───samples                         // 示例代码
│       mqtt_sample.c               // 软件包应用示例代码
├───tests                           // mqtt 功能测试程序
│   LICENSE                         // 软件包许可证
│   README.md                       // 软件包使用说明
└───SConscript                      // RT-Thread 默认的构建脚本
```

### 1.2 许可证

`my-mqtt` package 遵循 Eclipse Public License - v 1.0 许可，详见 `LICENSE` 文件。

* 维护：hichard
* 主页：https://github.com/hichard/mymqtt
