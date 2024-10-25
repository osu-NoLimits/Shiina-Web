package dev.osunolimits.modules;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;

import org.slf4j.LoggerFactory;
import org.yaml.snakeyaml.Yaml;

import ch.qos.logback.classic.Logger;
import dev.osunolimits.main.App;
import dev.osunolimits.models.Theme;

public class ThemeLoader {
    
    public static Logger logger = (Logger) LoggerFactory.getLogger(ThemeLoader.class);
    public static ArrayList<Theme> themes = new ArrayList<Theme>();
    
    public static void loadThemes() {
        File directory = new File("themes/");

        if (directory.exists() && directory.isDirectory()) {
            File[] files = directory.listFiles();

            if (files != null) {
                for (File file : files) {
                    if (file.isDirectory()) {
                        
                        File f = new File("themes/" + file.getName() + "/theme.yml");
                        if(f.exists() && !f.isDirectory()) {
                            Theme theme = Theme.loadTheme(f);
                            if (theme != null) {
                                themes.add(theme);
                                logger.info("Loaded theme: [" + file.getName() + "]");
                            }

                        } else {
                            logger.error("Theme [" + file.getName() + "] does not have a theme.yml file.");
                        }
                    }
                }
            } else {
                logger.warn("Themes directory is empty.");
            }
        } else {
            logger.error("Themes directory does not exist.");
        }

    }

    public static void selectTheme(String theme) {
        for (Theme t : themes) {
            if (t.getName().equals(theme)) {
                App.customization.put("theme", t.getName());
                Yaml yaml = new Yaml();
                String newCustomizations = yaml.dumpAsMap(App.customization);
                try {
                    Files.writeString(Paths.get(".config/customization.yml"), newCustomizations);
                } catch (IOException e) {
                    logger.error("Failed to apply theme change to customizations.yml");
                }
            }
        }
    }
}