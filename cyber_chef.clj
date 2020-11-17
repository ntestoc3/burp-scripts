(ns cyber-chef
  (:require [seesaw.core :as gui]
            [clojure.java.browse :refer [browse-url]]
            [clojure.string :as str]
            [taoensso.timbre :as log]
            [burp-clj.context-menu :as context-menu]
            [burp-clj.extender :as extender]
            [burp-clj.scripts :as scripts]
            [burp-clj.helper :as helper]))

(defn browse-cyber-chef
  [input]
  (->> (helper/base64-encode input)
       (str "https://gchq.github.io/CyberChef/#recipe=Magic(3,false,false,'')&input=" )
       browse-url))

(def menu-context #{:message-editor-request
                    :message-editor-response
                    :message-viewer-request
                    :message-viewer-response})


(defn cyber-chef-menu []
  (context-menu/make-context-menu
   menu-context
   (fn [invocation]
     (let [txt (context-menu/get-selected-text invocation)]
       (when-not (empty? txt)
         [(gui/menu-item :text "CyberChef Magic"
                         :enabled? true
                         :listen [:action (fn [e]
                                            (browse-cyber-chef txt))])])))))

(def reg (scripts/reg-script! :cyber-chef
                              {:name "cyber chef helper"
                               :version "0.0.1"
                               :min-burp-clj-version "0.1.0"
                               :context-menu {:cyber-chef (cyber-chef-menu)}}))
