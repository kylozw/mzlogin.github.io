---
layout: page
title: About
description: change the world
keywords: kylo, kylozw
comments: true
menu: 关于
permalink: /about/
---

<!-- 我是马壮，码而生，码而立。 -->

<!-- 仰慕「优雅编码的艺术」。 -->

<!-- ## 坚信 -->

<!-- * 熟能生巧 -->
<!-- * 努力改变人生 -->

## 联系

* GitHub：[@kylozw](https://github.com/kylozw)
<!-- * LinkedIn：[@kylozw](https://www.linkedin.com/in/kylozw) -->
* 博客：[{{ site.title }}]({{ site.url }})
* 微博: [@kylozw](http://weibo.com/kylozw)
<!-- * 知乎: [@kylozw](http://www.zhihu.com/people/kylozw) -->
<!-- * 豆瓣: [@黑の透明](http://www.douban.com/people/kylozw) -->

## Skill Keywords

#### Software Engineer Keywords
<div class="btn-inline">
    {% for keyword in site.skill_software_keywords %}
    <button class="btn btn-outline" type="button">{{ keyword }}</button>
    {% endfor %}
</div>

#### Mobile Developer Keywords
<div class="btn-inline">
    {% for keyword in site.skill_mobile_app_keywords %}
    <button class="btn btn-outline" type="button">{{ keyword }}</button>
    {% endfor %}
</div>

#### Windows Developer Keywords
<div class="btn-inline">
    {% for keyword in site.skill_windows_keywords %}
    <button class="btn btn-outline" type="button">{{ keyword }}</button>
    {% endfor %}
</div>
