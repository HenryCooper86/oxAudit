ADD app.jar /opt/app/app.jar
COPY --from=build /out/static /usr/share/nginx/html
