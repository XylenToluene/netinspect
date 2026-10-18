/* netinspect: применить выбранную тему до отрисовки страницы (без «вспышки»).
 * Подключается в <head> без defer. Выбор хранится только в браузере пользователя.
 */
(function () {
  'use strict';
  try {
    var t = window.localStorage.getItem('netinspect-theme');
    if (t === 'light' || t === 'dark') document.documentElement.setAttribute('data-theme', t);
  } catch (e) { /* хранилище недоступно — тема как в системе */ }
})();
