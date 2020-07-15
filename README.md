# Yara规则提取

在实际使用yara规则的过程中，规则库过大会明显拖慢程序的运行扫描效率，因此编写了此小工具，以用来剔除那些在某某年之前的过时的yara规则



## 依赖

`pip3 install plyara`



## 使用方法

`yaraExtract.exe -h 帮助文档 -i 输入目录 -o 输出目录 -t 在此年份之前`
