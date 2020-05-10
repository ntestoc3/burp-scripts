(ns testui
  (:require [seesaw.rsyntax :as rsyntax]
            [seesaw.font :as font]
            [seesaw.swingx :as guix]
            [burp-clj.utils :as utils]
            [burp-clj.extender :as extender]
            [seesaw.core :as gui])
  )



(comment

  (def fks (-> (javax.swing.UIManager/getDefaults)
               (.keys)))

  (font/default-font "TableHeader.font")

  (javax.swing.UIManager/getFont "Label.font")

  (->> (guix/titled-panel :title "Test"
                          :title-color :red
                          :content (guix/table-x :model [:columns [:age :height]
                                                         :rows [{:age 15 :height "test"}
                                                                {:age 18 :height "gogo"}]])
                          )
       (utils/show-ui))

  )
