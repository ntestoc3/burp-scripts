(ns webpack
  (:require [burp-clj.utils :as utils]
            [burp-clj.extender :as extender]
            [burp-clj.context-menu :as context-menu]
            [burp-clj.scripts :as scripts]
            [burp-clj.helper :as helper]
            [burp-clj.ui :as bui]
            [cheshire.core :as json]
            [me.raynes.fs :as fs]
            [clojure.java.io :as io]
            [clojure.string :as str]
            [com.climate.claypoole :as thread-pool]
            [diehard.core :as dh]
            [seesaw.core :as gui]
            [seesaw.mig :refer [mig-panel]]
            [taoensso.timbre :as log]
            [burp-clj.i18n :as i18n]
            [burp-clj.issue :as issue]
            [clojure.core.async :as async]
            [seesaw.border :as border]))

;;;; i18n
(def translations
  {:en {:missing       "**MISSING**"    ; Fallback for missing resources
        :script-name "webpack unmap"
        :issue {:name "webpack unmap"
                :detail "Burp Scanner has analysed the following JS mapping files can be accessed: <b>%1</b><br>%2<br>"
                :background "JS Source map files disclosure."
                :remediation-background "<a href='https://cwe.mitre.org/data/definitions/540.html'>CWE-540: Inclusion of Sensitive Information in Source Code</a>"}
        :save-dir-info "Save dir root:"
        :save-dir-tip "All js map files and unpacked webpack files use this folder as the root directory."
        :jsmap-root-info "jsmap root path:"
        :jsmap-root-tip "The js map file is saved under this path."
        :webpack-root-info "webpack root path:"
        :webpack-root-tip "The unpacked webpack file is saved in this path"
        :webpack-setting "webpack setting"
        }

   :zh {
        ;; issue显示中文乱码
        :script-name "webpack map文件解析"
        :save-dir-info "保存根文件夹:"
        :save-dir-tip "所有js map文件和解压的webpack文件以此文件夹作为根目录"
        :jsmap-root-info "js map文件路径:"
        :jsmap-root-tip "js map文件在此路径下保存"
        :webpack-root-info "webpack文件路径:"
        :webpack-root-tip "解压的webpack文件在此路径下保存"
        :webpack-setting "webpack设置"
        }})

(def tr (partial i18n/app-tr translations))

;;;;;; helper
(defn get-file-name
  "获取文件名，忽略?后缀的查询"
  [path]
  (-> (fs/base-name path)
      (str/split #"\?")
      first))

(defn get-file-parent
  "获取parent路径"
  [path]
  (str (fs/parent path)))

;;;;;; jsmap functions

(defn fetch-json-file
  "获取json文件

  如果服务器返回的不是合法的json文件则返回nil

  - `service` 用于发送请求的service
  - `req-info` request info "
  [service req-info]
  (let [url (str (helper/get-full-host service)
                 (:url req-info))]
    (dh/with-retry {:retry-on Exception
                    :delay-ms 2000 ;; 重试前等待时间
                    :fallback (fn [_ ex]
                                (log/warn :fetch-json-file url "failed."))
                    :on-retry (fn [val ex]
                                (log/warn :fetch-json-file url "error:" ex "retry..."))
                    :max-retries 3}
      (log/info :fetch-json-file url)
      (let [req-resp (-> (utils/build-request-raw req-info)
                         (helper/send-http-raw service))
            resp-info (-> (.getResponse req-resp)
                          utils/parse-response)]
        (when (= 200 (:status resp-info))
          (let [data (:body resp-info)]
            (try
              (json/decode data)
              req-resp
              (catch com.fasterxml.jackson.core.JsonParseException _
                (log/error :fetch-json-file "parse js map file error"
                           "url:" url
                           "body:" (when data
                                     (subs data 0
                                           (min 128
                                                (count data)))))))))))))

(defn canonical-path
  "获取文件的绝对路径，去掉./ ../"
  [f]
  (try
    (.getCanonicalPath f)
    (catch Exception e nil)))

(defn sub-dir?
  "检查`path`是否包含在`root-path`目录下"
  [path root-path]
  (let [base-path (-> root-path
                      fs/file
                      canonical-path
                      (str java.io.File/separator))
        real-path (-> (fs/file base-path path)
                      canonical-path)]
    (and base-path
         real-path
         (str/starts-with? real-path base-path))))

(defn format-webpack-path
  "格式化webpack路径，转换.为_dot"
  [p]
  (-> (str/replace p #"^webpack:///" "")
      (str/replace #"^\./" "_dot/")))

(defn unwebpack
  "解压webpack文件

  `jsmap-data` jsmap文件内容
  `save-dir` 保存解压文件的文件夹"
  [jsmap-data save-dir]
  (let [web-pack (json/decode jsmap-data keyword)]
    (when-not (= (count (:sources web-pack))
                 (count (:sourcesContent web-pack)))
      (log/warn :unwebpack
                "file mismatch,"
                "sources count:" (count (:sources web-pack))
                "sources content count:" (count (:sourcesContent web-pack))))
    (doseq [[index source-path] (->> (:sources web-pack)
                                     (map-indexed vector))]
      (let [save-path (fs/file save-dir (format-webpack-path source-path))]
        (if (sub-dir? source-path save-dir)
          (do
            (log/info :unwebpack "save to" save-path)
            (fs/mkdirs (fs/parent save-path))
            (spit save-path (-> (:sourcesContent web-pack)
                                (nth index))))
          (log/error :unwebpack
                     "save path not valid,source path:" source-path
                     "save dir:" save-dir
                     "save path:" save-path))))))

(defn get-chunck-filename
  [chunck-id chuncks]
  (str chunck-id
       "."
       (get chuncks chunck-id)
       ".js.map"))

(defn find-chuncks
  "查找所有chuncks,格式为{chunck-id chunck-tag ...}

  `webpack-root` 已解压的js map文件的根目录"
  [webpack-root]
  (let [bootstrap (fs/file webpack-root "webpack/bootstrap")]
    (when (fs/exists? bootstrap)
      (when-some [chuncks (->> (slurp bootstrap)
                               (re-find  #"\+\s*(\{.*\})\[chunkId\]\s*\+\s*\"\.js\"")
                               second)]
        (-> (str/replace chuncks ":" " ")
            (clojure.edn/read-string))))))

(defn find-all-chuncks-filename
  "查找并获取所有chuncks的文件名"
  [webpack-root]
  (let [chuncks (find-chuncks webpack-root)]
    (map (comp #(get-chunck-filename %1 chuncks) first)
         chuncks)))

;;;;;;;;;; script functions
(extender/defsetting :webpack/save-dir (str (fs/tmpdir)))
(extender/defsetting :webpack/jsmap-root "mapfiles")
(extender/defsetting :webpack/webpack-root "webpack")

(defn jsmap-exists?
  [host jsmap-path]
  (-> (fs/file (get-save-dir)
               host
               (get-jsmap-root)
               jsmap-path)
      (fs/exists?)))

(defn save-unpack-jsmap
  "请求jsmap文件，并解压保存

  如果成功，返回 IHttpRequestResponse"
  [service req-info file-name]
  (let [new-req-info (update req-info
                             :url
                             #(str (get-file-parent %1) "/" file-name))]
    (when-let [req-resp (fetch-json-file service new-req-info)]
      (let [data (-> (.getResponse req-resp)
                     (utils/parse-response)
                     :body)
            jsmap-dir (fs/file (get-save-dir)
                               (:host service)
                               (get-jsmap-root))
            webpack-dir (fs/file (get-save-dir)
                                 (:host service)
                                 (get-webpack-root))
            local-file-path (fs/file jsmap-dir file-name)]
        (log/info :save-unpack-jsmap "save to" local-file-path)
        (fs/mkdirs jsmap-dir)
        (fs/mkdirs webpack-dir)
        (spit local-file-path data)
        (unwebpack data webpack-dir)
        req-resp))))

(def jsmap-req> (async/chan 32))
(def kill> (async/chan))
(def err< (async/chan))

(defn jsmap-error-handler
  []
  (async/go-loop [coll (async/alts! [kill> err<] :priority true)]
    (let [[e ch] coll]
      (if (= ch kill>)
        (log/info :error-handler "shutdown")
        (do (if (string? e)
              (log/error e)
              (log/error (.getMessage e)))
            (recur (async/alts! [kill> err<] :priority true)))))))

(defn start-jsmap-service
  []
  (log/info :jsmap-service "start.")
  (async/go-loop [coll (async/alts! [kill> jsmap-req>] :priority true)]
    (let [[x ch] coll]
      (if (= ch kill>)
        (log/info :jsmap-service "recevie msg in kill> channel; shutdown")
        (do
          (try
            (log/info :jsmap-service "recv" x)
            (let [{:keys [service req-resp file-name]} x
                  req-info (utils/parse-request (.getRequest req-resp))
                  ok-req-resp (-> (async/thread
                                    (save-unpack-jsmap service req-info file-name))
                                  async/<!)]
              (when ok-req-resp
                (let [url (.getUrl ok-req-resp)
                      webpack-dir (fs/file (get-save-dir)
                                           (:host service)
                                           (get-webpack-root))
                      chunck-files (find-all-chuncks-filename webpack-dir)
                      chunck-infos (when-not (empty? chunck-files)
                                     (log/info :save-unpack-jsmap
                                               "found chuncks total:"
                                               (count chunck-files))
                                     (doseq [file-name chunck-files]
                                       (-> (async/thread
                                             (save-unpack-jsmap service req-info file-name))
                                           async/<!))
                                     (str "and found <b>chunck files</b>:<br>"
                                          (str/join "<br>" chunck-files)))]
                  ;; 返回issue list会添加失败
                  (-> (issue/make-issue {:url url
                                         :name (tr :issue/name)
                                         :confidence :certain
                                         :severity :info
                                         :http-messages [req-resp]
                                         :http-service (helper/->http-service service)
                                         :background (tr :issue/background)
                                         :remediation-background (tr :issue/remediation-background)
                                         :detail (tr :issue/detail
                                                     url
                                                     chunck-infos)})
                      (issue/add-issue!))
                  (log/info :jsmap-service "add new issue:" (.getUrl ok-req-resp)))))
            (catch Exception e
              (async/>! err< e)))
          (recur (async/alts! [kill> jsmap-req>] :priority true)))))))

(defn jsmap-scan
  [req-resp]
  (let [service (-> (.getHttpService req-resp)
                    helper/parse-http-service)
        path (-> (.getUrl req-resp)
                 (.getFile))
        file-name (str (get-file-name path)
                       ".map")]
    (when (and (str/includes? path ".js")
               (-> (.getResponse req-resp)
                   (utils/->string)
                   (str/ends-with? ".js.map"))
               (not (jsmap-exists?
                     (:host service)
                     file-name)))
      (log/info :jsmap-scan "get" file-name)
      (async/put! jsmap-req> {:service service
                              :file-name file-name
                              :req-resp req-resp})
      nil)))

(defn jsmap-issue-check
  []
  (issue/make-scanner-check {:passive-scan-fn jsmap-scan}))

;;;;;;;;;;;; gui

(defn make-webpack-setting
  []
  (mig-panel
   :border (border/empty-border :left 10 :top 10)
   :items [[(tr :save-dir-info)]
           [(gui/text :text (get-save-dir)
                      :id :save-dir-txt
                      :tip (tr :save-dir-tip)
                      :listen [:document
                               #(-> (gui/text %)
                                    set-save-dir!)])
            "grow, wmin 300"]

           [(bui/choose-dir-btn (get-save-dir) [:#save-dir-txt])
            "wrap"]

           [(tr :jsmap-root-info)]
           [(gui/text :text (get-jsmap-root)
                      :tip (tr :jsmap-root-tip)
                      :listen [:document
                               #(-> (gui/text %)
                                    set-jsmap-root!)])
            "wrap, spanx, grow"]

           [(tr :webpack-root-info)]
           [(gui/text :text (get-webpack-root)
                      :tip (tr :webpack-root-tip)
                      :listen [:document
                               #(-> (gui/text %)
                                    set-webpack-root!)])
            "wrap, spanx, grow, wmin 300"]
           ]))


(def reg (scripts/reg-script! :webpack
                              {:name (tr :script-name)
                               :version "0.1.0"
                               :min-burp-clj-version "0.4.14"
                               :scanner-check {:webpack/jsmap-scan (jsmap-issue-check)}
                               :enable-callback (fn [_]
                                                  (start-jsmap-service)
                                                  (jsmap-error-handler))
                               :disable-callback (fn [_]
                                                   (async/put! kill> true))
                               :tab {:webpack/setting
                                     {:captain (tr :webpack-setting)
                                      :view (make-webpack-setting)}}}))
