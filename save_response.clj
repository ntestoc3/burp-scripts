(ns save-response
  (:require [seesaw.core :as gui]
            [clojure.string :as str]
            [taoensso.timbre :as log]
            [burp-clj.context-menu :as context-menu]
            [burp-clj.extender :as extender]
            [burp-clj.scripts :as scripts]
            [burp-clj.http-message :as http-message]
            [burp-clj.helper :as helper]
            [me.raynes.fs :as fs]
            [seesaw.mig :refer [mig-panel]]
            [seesaw.clipboard :as clip]
            [seesaw.border :as border]
            [clojure.java.browse :refer [browse-url]]
            [burp-clj.utils :as utils]
            [burp-clj.ui :as ui]
            [burp-clj.i18n :as i18n]))

;;;;;; i18n
(def translations
  {:en {:missing       "**MISSING**"    ; Fallback for missing resources
        :script-name "save response"
        :menu-text "Save response body"
        :select-dir-text "select directory to save:"
        :save-ok "all response body saved."
        :open-dir "Open directory"
        :cancel "Cancel"
        }

   :zh {
        :script-name "保存response"
        :menu-text "保存响应内容"
        :select-dir-text "选择要保存的文件夹:"
        :save-ok "保存完毕"
        :open-dir "打开文件夹"
        :cancel "取消"
        }})

(def tr (partial i18n/app-tr translations))

;;;;;;;;;;;;;

(extender/defsetting :save-response/last-dir (str (fs/home)))

(def menu-context #{:target-site-map-tree
                    :target-site-map-table
                    :message-viewer-response
                    :search-results
                    :proxy-history})

(defn select-dir-dlg
  []
  (utils/add-dep [])
  (ui/input-dir {:title (tr :script-name)
                 :parent (helper/get-burp-clj-view)
                 :default-path (get-last-dir)
                 :text (tr :select-dir-text)}))

(defn show-ok-dlg
  []
  (let [open-dir (gui/button :text (tr :open-dir)
                             :listen [:action (fn [e]
                                                (gui/return-from-dialog e :open-dir))])
        cancel-dir (gui/button :text (tr :cancel)
                               :listen [:action (fn [e]
                                                  (gui/return-from-dialog e :cancel))])]
    (-> (gui/dialog  :parent (helper/get-burp-clj-view)
                     :content (tr :save-ok)
                     :title (tr :script-name)
                     :options [open-dir cancel-dir]
                     :default-option cancel-dir)
        (gui/pack!)
        (gui/show!))))

(defn save-all
  [base-dir messages]
  (doseq [req-resp messages]
    (try
      (let [info (http-message/parse-http-req-resp req-resp)
            path (-> (:request/url info)
                     (str/replace #"\?.*$" ""))
            save-path (fs/file base-dir
                               (str (:host info) path))]
        (when (:response/body info)
          (when-not (fs/exists? save-path)
            (log/info :save-all "save:" save-path)
            (fs/mkdirs (fs/parent save-path))
            (-> (:response/body info)
                (utils/->string "UTF-8")
                (->> (spit save-path))))))
      (catch Exception e
        (log/error :save-all "error:" e "url:" (.getUrl req-resp)))))
  (when (= :open-dir (show-ok-dlg))
    (-> (fs/file base-dir)
        (.toURI)
        str
        browse-url)))

(defn save-response-menu []
  (context-menu/make-context-menu
   menu-context
   (fn [invocation]
     [(gui/menu-item :text (tr :menu-text)
                     :listen [:action
                              (fn [e]
                                (when-let [dir (select-dir-dlg)]
                                  (set-last-dir! dir)
                                  (->> (context-menu/get-selected-messge invocation)
                                       (save-all dir))))])])))

(def reg (scripts/reg-script! :save-response
                              {:name (tr :script-name)
                               :version "0.0.1"
                               :min-burp-clj-version "0.5.0"
                               :context-menu {:save-response (save-response-menu)}}))
