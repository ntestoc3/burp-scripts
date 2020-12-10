
# 用于burp-clj的脚本文件

## cyber-chef

快速发送到cyber-chef, chrome浏览器对有些字符串会拦截

## shiro-check 

检测是否使用了shiro框架,如果发现则添加issue

## nrepl

开启clojure nrepl server, 方便调试script代码

## ip-loc 

comment中添加ip地址显示

## jslink

查找js文件中的链接,如果发现链接则添加issue

或者手动选择消息进行分析,在burp重启后方便重新获取链接

结果界面方便处理和复制，用作burp Intruder的payload


感谢 https://github.com/portswigger/js-link-finder 的burp插件思路

感谢 https://github.com/GerbenJavado/LinkFinder 的正则表达式

## easy search 
  方便在repeater中搜索文本，有时要查看输入的内容是否在响应中存在，手动复制比较麻烦，使用此脚本，
  在repeater的request或response中选中文本， 然后按鼠标右键，自动在response中搜索选中的文本

## host header check 
  检测host header漏洞
  
  使用方法: 右键选择Send request to Host-Header-check
  
  感谢 https://portswigger.net/web-security/host-header/exploiting#how-to-test-for-vulnerabilities-using-the-http-host-header 提供的检测方法

## webpack
  检测js map文件，如果包含源码则还原整个webpack.

## save response
  保存选中项的response body到指定目录，保持网站目录结构

