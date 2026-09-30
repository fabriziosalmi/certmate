class CertmateCli < Formula
  include Language::Python::Virtualenv

  desc "Command-line client for CertMate, the self-hosted TLS certificate manager"
  homepage "https://github.com/fabriziosalmi/certmate"
  url "https://files.pythonhosted.org/packages/48/08/d106d84df69401fb6dbeede678b72de4a576217250e916570bfc3e2cb4dd/certmate_cli-0.1.5.tar.gz"
  sha256 "926c5db9b9f4963f7ea031fff2cb3a7a206b7e767cf2adec819aaf14f4a2bb6e"
  license "MIT"

  depends_on "certifi"
  depends_on "python@3.14"

  resource "annotated-doc" do
    url "https://files.pythonhosted.org/packages/5a/8e/38aa427ed5402449e226975b649c5dc73ccadfefeb95e6aecb8f8ea4b6b6/annotated_doc-0.0.5.tar.gz"
    sha256 "c7e58ce09192557605d8bbd92836d7e1d520ac9580096042c0bfd197efacf1bb"
  end

  resource "anyio" do
    url "https://files.pythonhosted.org/packages/a9/d2/f4d173e22df740bc37b1db102b386ba719b66e95b0f0d751f556b387e6d2/anyio-4.15.1.tar.gz"
    sha256 "9f28306018cbd6d329e64a36d58256edff76dd996fe423bc957326e578b82a94"
  end

  resource "certmate-sdk" do
    url "https://files.pythonhosted.org/packages/91/ce/51d3ab9bb09126c2da7a476e713a846a9e0adcd8693e4ce9df1fd3107876/certmate_sdk-0.1.5.tar.gz"
    sha256 "84940baa0869d42fc7ff9e1c74f3b42786f0eba27b25b045b3672e2aa11b34d7"
  end

  resource "h11" do
    url "https://files.pythonhosted.org/packages/01/ee/02a2c011bdab74c6fb3c75474d40b3052059d95df7e73351460c8588d963/h11-0.16.0.tar.gz"
    sha256 "4e35b956cf45792e4caa5885e69fba00bdbc6ffafbfa020300e549b208ee5ff1"
  end

  resource "httpcore" do
    url "https://files.pythonhosted.org/packages/06/94/82699a10bca87a5556c9c59b5963f2d039dbd239f25bc2a63907a05a14cb/httpcore-1.0.9.tar.gz"
    sha256 "6e34463af53fd2ab5d807f399a9b45ea31c3dfa2276f15a2c3f00afff6e176e8"
  end

  resource "httpx" do
    url "https://files.pythonhosted.org/packages/b1/df/48c586a5fe32a0f01324ee087459e112ebb7224f646c0b5023f5e79e9956/httpx-0.28.1.tar.gz"
    sha256 "75e98c5f16b0f35b567856f597f06ff2270a374470a5c2392242528e3e3e42fc"
  end

  resource "idna" do
    url "https://files.pythonhosted.org/packages/f5/08/8eea9d4b8302028f3abb2c0813953f7aec26d33b7a8960ed760e65ff29fa/idna-3.20.tar.gz"
    sha256 "a7db850025b95ded1eae8a46181a1a6c56c92c96f0e2b005d9ff8dc0210cab44"
  end

  resource "markdown-it-py" do
    url "https://files.pythonhosted.org/packages/06/ff/7841249c247aa650a76b9ee4bbaeae59370dc8bfd2f6c01f3630c35eb134/markdown_it_py-4.2.0.tar.gz"
    sha256 "04a21681d6fbb623de53f6f364d352309d4094dd4194040a10fd51833e418d49"
  end

  resource "mdurl" do
    url "https://files.pythonhosted.org/packages/d6/54/cfe61301667036ec958cb99bd3efefba235e65cdeb9c84d24a8293ba1d90/mdurl-0.1.2.tar.gz"
    sha256 "bb413d29f5eea38f31dd4754dd7377d4465116fb207585f97bf925588687c1ba"
  end

  resource "pygments" do
    url "https://files.pythonhosted.org/packages/49/2e/ced460408999b33da6b31b0021b0f37d329e202d4169aeb164493778f25b/pygments-2.21.0.tar.gz"
    sha256 "610ca751c9bc2492b38eb9a38a7fbc93edbbb2d7182edaf34e66ae493dee5c8c"
  end

  resource "rich" do
    url "https://files.pythonhosted.org/packages/c0/8f/0722ca900cc807c13a6a0c696dacf35430f72e0ec571c4275d2371fca3e9/rich-15.0.0.tar.gz"
    sha256 "edd07a4824c6b40189fb7ac9bc4c52536e9780fbbfbddf6f1e2502c31b068c36"
  end

  resource "shellingham" do
    url "https://files.pythonhosted.org/packages/58/15/8b3609fd3830ef7b27b655beb4b4e9c62313a4e8da8c676e142cc210d58e/shellingham-1.5.4.tar.gz"
    sha256 "8dbca0739d487e5bd35ab3ca4b36e11c4078f3a234bfce294b0a0291363404de"
  end

  resource "typer" do
    url "https://files.pythonhosted.org/packages/16/f7/57713ba479fd405eb76de31404b2c744c289e336b2d999511ebf51e496f7/typer-0.27.2.tar.gz"
    sha256 "269b7eb9d3c202ca84b4bc9618cb04ebb43d3d4d1e567e4c768607232c05f945"
  end

  resource "typing-extensions" do
    url "https://files.pythonhosted.org/packages/f6/cc/6253133b5bb138fc3306cebfbda2c520f545d36b5be2c7255cc528bb45d6/typing_extensions-4.16.0.tar.gz"
    sha256 "dc983d19a509c94dba722ee6abd33940f7c05a89e243c47e907eb4db6f1a43e5"
  end

  def install
    virtualenv_install_with_resources
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/certmate --version")
    # No server needed: an unreachable URL must fail cleanly, not crash.
    output = shell_output("#{bin}/certmate --url http://127.0.0.1:9 health 2>&1", 1)
    refute_match "Traceback", output
  end
end
