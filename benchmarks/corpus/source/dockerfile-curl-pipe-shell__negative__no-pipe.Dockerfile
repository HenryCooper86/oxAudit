RUN curl --proto '=https' --tlsv1.2 -sSf https://example.com/tool.tar.gz -o tool.tar.gz
RUN tar xzf tool.tar.gz
