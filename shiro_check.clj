(ns shiro-check
  (:require [burp-clj.proxy :as proxy]
            [burp-clj.helper :as helper]
            [taoensso.timbre :as log]
            [burp-clj.scripts :as scripts]
            ))

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
              org-comment (.getComment req-resp)]
          (when (->> resp-cookies
                     (take-while #(and (= (:name %) "rememberMe")
                                       (= (:value %) "deleteMe")))
                     seq)
            (doto req-resp
              (.setHighlight "orange")
              (.setComment (str "maybe Shiro! " org-comment)))))))))

(defn shiro-check-proxy []
  (proxy/make-proxy-proc shiro-check))

(def reg (scripts/reg-script! :shiro-check ;; 脚本唯一id,如果执行多次,最后一次执行的生效
                              {:name "jsp shiro check" ;; 脚本名字
                               :version "0.0.1" ;; 当前版本号
                               :min-burp-clj-version "0.1.1" ;; burp-clj最低版本号

                               ;; 添加 proxy listener
                               :proxy-listener {:shiro-check/cookie-check ;; proxy listener的key,自己指定，不过所有脚本的key不能有重复，建议使用带命名空间的keyword
                                                (shiro-check-proxy)

                                                ;; 可以指定多个proxy listener, 使用不同的key即可
                                                }
                               }))
