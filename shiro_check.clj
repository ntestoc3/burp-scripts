(ns shiro-check
  (:require [burp-clj.proxy :as proxy]
            [burp-clj.helper :as helper]
            [burp-clj.i18n :as i18n]
            [burp-clj.issue :as issue]
            [taoensso.timbre :as log]
            [burp-clj.scripts :as scripts]
            ))

;;;;;; i18n
(def translations
  {:en {:missing       "**MISSING**"    ; Fallback for missing resources
        :script-name "JSP shiro check"
        :issue {:name "JSP shiro check"
                :detail "Burp Scanner has analysed the following JSP file for shiro check <b>%1</b><br><br>"
                :background "JSP page maybe use shiro framework"
                :remediation-background "JSP shiro check is an <b>informational</b> finding only.<br>"}
        }

   :zh {:script-name "JSP shiro检测"
        }})

(def tr (partial i18n/app-tr translations))

;;;;;;;;;;;

(defn shiro-check
  [is-req msg]
  (let [req-resp (.getMessageInfo msg)
        req (.getRequest req-resp)
        jsession-id (or (helper/get-request-parameter req "JSESSIONID")
                        (helper/get-request-parameter req "SESSION"))]
    (when jsession-id
      (if is-req
        (when (not (helper/get-request-parameter req "rememberMe"))
          (->> (helper/build-parameter "rememberMe" "test" :cookie)
               (helper/add-parameter req)
               (.setRequest req-resp)))
        (let [resp-cookies (->> (.getResponse req-resp)
                                helper/analyze-response
                                .getCookies
                                (map helper/parse-cookie))
              url (.getUrl req-resp)]
          (when (->> resp-cookies
                     (take-while #(and (= (:name %) "rememberMe")
                                       (= (:value %) "deleteMe")))
                     seq)
            (-> (issue/make-issue {:url url
                                   :name (tr :issue/name)
                                   :confidence :tentative
                                   :severity :low
                                   :http-messages [req-resp]
                                   :http-service (.getHttpService req-resp)
                                   :background (tr :issue/background)
                                   :remediation-background (tr :issue/remediation-background)
                                   :detail (tr :issue/detail url)})
                issue/add-issue!)))))))

(defn shiro-check-proxy []
  (proxy/make-proxy-proc shiro-check))

(def reg (scripts/reg-script! :shiro-check ;; 脚本唯一id,如果执行多次,最后一次执行的生效
                              {:name (tr :script-name) ;; 脚本名字
                               :version "0.1.0" ;; 当前版本号
                               :min-burp-clj-version "0.4.12" ;; burp-clj最低版本号

                               ;; 添加 proxy listener
                               :proxy-listener {:shiro-check/cookie-check
                                                ;; proxy listener的key,自己指定，不过所有脚本的key不能有重复，建议使用带命名空间的keyword
                                                (shiro-check-proxy)

                                                ;; 可以指定多个proxy listener, 使用不同的key即可
                                                }
                               }))
