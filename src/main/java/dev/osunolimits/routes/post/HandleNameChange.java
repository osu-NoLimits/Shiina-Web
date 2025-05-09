package dev.osunolimits.routes.post;


import com.google.gson.Gson;

import dev.osunolimits.main.App;
import dev.osunolimits.models.UserInfoObject;
import dev.osunolimits.modules.Shiina;
import dev.osunolimits.modules.ShiinaRoute;
import dev.osunolimits.modules.ShiinaRoute.ShiinaRequest;
import dev.osunolimits.plugins.events.actions.OnUserNameChangeEvent;
import dev.osunolimits.routes.ap.api.PubSubModels;
import dev.osunolimits.routes.ap.api.PubSubModels.NameChangeInput;
import dev.osunolimits.utils.osu.PermissionHelper;
import spark.Request;
import spark.Response;

public class HandleNameChange extends Shiina {
    private final Gson GSON;
    public HandleNameChange() {
        this.GSON = new Gson();
    }

    @Override
    public Object handle(Request req, Response res) throws Exception {
       ShiinaRequest shiina = new ShiinaRoute().handle(req, res);

        if (!shiina.loggedIn) {
            // TODO: impl customization redirect on login
            return redirect(res, shiina, "/login?path=customization");
        }

        if(!PermissionHelper.hasPrivileges(shiina.user.priv, PermissionHelper.Privileges.SUPPORTER)) {
            return redirect(res, shiina, "/settings?error=You do not have permission to do this");
        }

        String newName = req.queryParams("newname");
        String newSafeName = newName.toLowerCase().replaceAll(" ", "_");
        if (newName == null || newName.isEmpty() ||
            newName.matches("^[\\p{Z}\\s]") || newName.matches("[\\p{Z}\\s]$")) {
            return redirect(res, shiina, "/settings?error=Invalid name");
        }

        String usernameCheckSql = "SELECT `id` FROM `users` WHERE `name` = ?";
        if(shiina.mysql.Query(usernameCheckSql, newName).next()) {
            return redirect(res, shiina, "/settings?error=Name already taken");
        }
        
        UserInfoObject obj = GSON.fromJson(App.jedisPool.get("shiina:user:" + shiina.user.id), UserInfoObject.class); 
        obj.name = newName;
        obj.safe_name = newSafeName;
        String userJson = GSON.toJson(obj);
        App.jedisPool.set("shiina:user:" + shiina.user.id, userJson);

        shiina.mysql.Exec("UPDATE `users` SET `name`=?,`safe_name`=? WHERE `id` = ?", newName, newSafeName, shiina.user.id);

        NameChangeInput input = new PubSubModels().new NameChangeInput();
        input.id = shiina.user.id;
        input.name = newName;
        App.jedisPool.publish("name_change", GSON.toJson(input));
        
        new OnUserNameChangeEvent(shiina.user.id, shiina.user.name, newName).callListeners();

        return redirect(res, shiina, "/settings?info=Name was changed successfully");
    }
}
