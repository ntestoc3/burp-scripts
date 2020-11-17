
# 用于burp-clj的脚本文件

## cyber-chef

快速发送到cyber-chef, chrome浏览器对有些字符串会拦截

## shiro-check 

检测是否使用了shiro框架

## nrepl

开启clojure nrepl server, 方便调试script代码

## ip-loc 

comment中添加ip地址显示

## jslink

查找js文件中的链接,方便处理和复制，用作burp Intruder的payload

感谢 https://github.com/portswigger/js-link-finder 的burp插件思路

感谢 https://github.com/GerbenJavado/LinkFinder 的正则表达式

## easy search 
  方便在repeater中搜索文本，有时要查看输入的内容是否在响应中存在，手动复制比较麻烦，使用此脚本，
  在repeater的request或response中选中文本， 然后按鼠标右键，自动在response中搜索选中的文本
