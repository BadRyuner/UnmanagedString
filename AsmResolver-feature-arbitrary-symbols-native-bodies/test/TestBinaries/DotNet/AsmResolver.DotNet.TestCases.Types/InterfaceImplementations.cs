namespace AsmResolver.DotNet.TestCases.Types
{
    public class InterfaceImplementations : IInterface1, IInterface2
    {
        public void Interface1Method()
        {
        }

        void IInterface2.Interface2Method()
        {
        }
    }
}